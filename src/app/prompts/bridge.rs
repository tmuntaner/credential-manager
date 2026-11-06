use super::model::{NoticeEvent, NoticeId, PromptAnswer, PromptId, PromptRequest, UiEvent};
use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{
    ChoicePrompt, ConfirmPrompt, SecretPrompt, UserNotice,
};
use crate::domain::ports::notifier::{Notifier, NotifyError};
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::{oneshot, watch};

/// Tells the flow that waits on a notice which notice the user gave up on. It keeps the last value, so a cancel
/// that comes before the flow starts waiting is not lost.
type CancelSignal = Arc<watch::Sender<Option<NoticeId>>>;

/// Where the events for the window go.
pub trait PromptSink: Send + Sync + 'static {
    fn emit(&self, event: UiEvent);
}

/// The error for an answer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnswerError {
    #[error("there is no such open question")]
    Unknown,
    #[error("the answer does not fit the question")]
    Mismatch,
}

/// The shape of a pending question.
#[derive(Clone, Copy)]
enum Expect {
    Secret,
    Confirm,
    Choice { options: usize },
}

struct Pending {
    expect: Expect,
    reply: oneshot::Sender<PromptAnswer>,
}

/// Bridges the questions from the domain to the GUI window.
pub struct PromptBridge<S: PromptSink> {
    sink: S,
    next_id: AtomicU64,
    pending: Mutex<HashMap<PromptId, Pending>>,
    next_notice: AtomicU64,
    /// The notices that wait for the user, by what to wake when the user gives up (see
    /// [`PromptBridge::cancel_notice`]).
    waiting: Mutex<HashMap<NoticeId, CancelSignal>>,
}

/// Removes the question when the flow which prompted a user is dropped.
/// This lets the window know to close it.
struct Registration<'a, S: PromptSink> {
    bridge: &'a PromptBridge<S>,
    id: PromptId,
}

impl<S: PromptSink> Drop for Registration<'_, S> {
    fn drop(&mut self) {
        let was_open = self.bridge.lock().remove(&self.id).is_some();
        if was_open {
            self.bridge.sink.emit(UiEvent::Withdraw { id: self.id });
        }
    }
}

impl<S: PromptSink> PromptBridge<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            next_notice: AtomicU64::new(1),
            waiting: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PromptId, Pending>> {
        // A panic while holding the lock leaves the map consistent, so a poisoned lock is fine to use.
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hands an answer back to the application flow.
    pub fn answer(&self, id: PromptId, answer: PromptAnswer) -> Result<(), AnswerError> {
        let mut pending = self.lock();

        // try to get the entry from list of pending prompts.
        let entry = pending.get(&id).ok_or(AnswerError::Unknown)?;

        // ensure that the input from the user is correct
        let fits = match (&answer, entry.expect) {
            (PromptAnswer::Cancel, _) => true,
            (PromptAnswer::Secret { .. }, Expect::Secret) => true,
            (PromptAnswer::Confirm { .. }, Expect::Confirm) => true,
            (PromptAnswer::Choice { index }, Expect::Choice { options }) => *index < options, //  outside the bounds of the options list
            _ => false,
        };
        if !fits {
            return Err(AnswerError::Mismatch);
        }

        // remove the entry from the pending prompts
        let entry = pending.remove(&id).ok_or(AnswerError::Unknown)?;

        // try to send the reply, but the prompt may already be gone, so ignore the error.
        let _ = entry.reply.send(answer);

        Ok(())
    }

    /// Cancels all open prompts.
    /// This will most likely be called when the window is closing.
    pub fn cancel_all(&self) {
        let open: Vec<_> = self.lock().drain().collect();

        for (id, entry) in open {
            let _ = entry.reply.send(PromptAnswer::Cancel);
            self.sink.emit(UiEvent::Withdraw { id });
        }
    }

    /// The user gave up waiting on the notice.
    /// Only the flow which showed this notice stops waiting.
    /// The other flows are not affected. Cancelling a notice that is gone is a no-op.
    pub fn cancel_notice(&self, id: NoticeId) {
        let signal = self.lock_waiting().remove(&id);

        if let Some(signal) = signal {
            signal.send_replace(Some(id));
        }
    }

    /// Takes down all notices from the screen.
    /// This is used when the application flow which called the notices ended.
    pub fn clear_notices(&self) {
        self.lock_waiting().clear();
        self.sink.emit(UiEvent::ClearNotices);
    }

    fn lock_waiting(&self) -> std::sync::MutexGuard<'_, HashMap<NoticeId, CancelSignal>> {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Prompts the user within an application flow.
    async fn ask(
        &self,
        expect: Expect,
        request: impl FnOnce(PromptId) -> PromptRequest,
    ) -> Result<PromptAnswer, InteractionError> {
        let id = self.next_id();

        let (reply, answer) = oneshot::channel();
        self.lock().insert(id, Pending { expect, reply });

        let _registration = Registration { bridge: self, id };

        self.sink.emit(UiEvent::Prompt {
            prompt: request(id),
        });

        match answer.await {
            Ok(PromptAnswer::Cancel) | Err(_) => Err(InteractionError::Cancelled),
            Ok(answer) => Ok(answer),
        }
    }

    /// Retrieves the next ID to post the next message under.
    fn next_id(&self) -> PromptId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// The [`UserInteraction`] of the app: questions in the window.
pub struct WindowInteraction<S: PromptSink> {
    bridge: Arc<PromptBridge<S>>,
}

impl<S: PromptSink> WindowInteraction<S> {
    pub fn new(bridge: Arc<PromptBridge<S>>) -> Self {
        Self { bridge }
    }
}

fn unexpected() -> InteractionError {
    InteractionError::failed("the window answered with something else than asked")
}

#[async_trait(?Send)]
impl<S: PromptSink> UserInteraction for WindowInteraction<S> {
    async fn ask_secret(&self, prompt: SecretPrompt) -> Result<SafeSecret, InteractionError> {
        let answer = self
            .bridge
            .ask(Expect::Secret, |id| PromptRequest::Secret {
                id,
                title: prompt.title,
                description: prompt.description,
                label: prompt.label,
                error: prompt.error,
                kind: prompt.kind,
            })
            .await?;

        match answer {
            PromptAnswer::Secret { value } => Ok(value.into_secret()),
            _ => Err(unexpected()),
        }
    }

    async fn confirm(&self, prompt: ConfirmPrompt) -> Result<bool, InteractionError> {
        let answer = self
            .bridge
            .ask(Expect::Confirm, |id| PromptRequest::Confirm {
                id,
                title: prompt.title,
                description: prompt.description,
                ok_label: prompt.ok_label,
                cancel_label: prompt.cancel_label,
            })
            .await?;

        match answer {
            PromptAnswer::Confirm { accepted } => Ok(accepted),
            _ => Err(unexpected()),
        }
    }

    async fn choose(&self, prompt: &ChoicePrompt) -> Result<usize, InteractionError> {
        let options = prompt.options.len();
        let answer = self
            .bridge
            .ask(Expect::Choice { options }, |id| PromptRequest::Choice {
                id,
                title: prompt.title.clone(),
                description: prompt.description.clone(),
                options: prompt.options.clone(),
            })
            .await?;

        match answer {
            PromptAnswer::Choice { index } => Ok(index),
            _ => Err(unexpected()),
        }
    }
}

/// The [`Notifier`] for the app.
/// Notices stay in the window until dismissed or replaced.
/// This is where notices like "touch your security key" show.
/// It provides information that the user should be aware of.
///
/// Make one notifier per flow: `dismissed` waits on the notice that this notifier showed last.
pub struct WindowNotifier<S: PromptSink> {
    bridge: Arc<PromptBridge<S>>,
    /// Where the user's cancel arrives.
    signal: CancelSignal,
    /// The last notice of this notifier that waits for the user.
    current: Mutex<Option<NoticeId>>,
}

impl<S: PromptSink> WindowNotifier<S> {
    pub fn new(bridge: Arc<PromptBridge<S>>) -> Self {
        Self {
            bridge,
            signal: Arc::new(watch::channel(None).0),
            current: Mutex::new(None),
        }
    }

    fn lock_current(&self) -> std::sync::MutexGuard<'_, Option<NoticeId>> {
        self.current.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<S: PromptSink> Drop for WindowNotifier<S> {
    fn drop(&mut self) {
        let id = *self.lock_current();
        if let Some(id) = id {
            self.bridge.lock_waiting().remove(&id);
        }
    }
}

#[async_trait(?Send)]
impl<S: PromptSink> Notifier for WindowNotifier<S> {
    async fn notify(&self, notice: &UserNotice) -> Result<(), NotifyError> {
        let id = self.bridge.next_notice.fetch_add(1, Ordering::Relaxed);

        if notice.awaiting_action {
            // The wait is for this notice only, so a click on an earlier one cannot cancel it.
            let mut current = self.lock_current();
            let mut waiting = self.bridge.lock_waiting();
            if let Some(old) = current.replace(id) {
                waiting.remove(&old);
            }
            waiting.insert(id, self.signal.clone());
        }

        self.bridge.sink.emit(UiEvent::Notice {
            notice: NoticeEvent {
                id,
                level: notice.level,
                message: notice.message.clone(),
                cancellable: notice.awaiting_action,
            },
        });

        Ok(())
    }

    async fn dismissed(&self) {
        let mut cancelled = self.signal.subscribe();

        // Only a cancel of the notice shown last counts, whenever the wait started.
        let wait = cancelled
            .wait_for(|cancelled| cancelled.is_some() && *cancelled == *self.lock_current());
        if wait.await.is_err() {
            std::future::pending::<()>().await
        }

        // The cancel is consumed: a later call must wait for a new notice, not return at once.
        let id = self.lock_current().take();
        if let Some(id) = id {
            self.bridge.lock_waiting().remove(&id);
        }
        self.signal.send_replace(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::prompts::model::SecretText;
    use crate::domain::models::user_interaction::SecretKind;

    #[derive(Default, Clone)]
    struct FakeSink(Arc<Mutex<Vec<UiEvent>>>);

    impl PromptSink for FakeSink {
        fn emit(&self, event: UiEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl FakeSink {
        fn events(&self) -> Vec<UiEvent> {
            self.0.lock().unwrap().clone()
        }

        /// The id of the first prompt shown, once it is shown.
        async fn first_prompt(&self) -> PromptId {
            loop {
                let found = self.events().iter().find_map(|event| match event {
                    UiEvent::Prompt { prompt } => Some(prompt.id()),
                    _ => None,
                });
                if let Some(id) = found {
                    return id;
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn setup() -> (FakeSink, Arc<PromptBridge<FakeSink>>) {
        let sink = FakeSink::default();
        (sink.clone(), Arc::new(PromptBridge::new(sink)))
    }

    #[tokio::test]
    async fn a_secret_is_asked_and_answered() {
        let (sink, bridge) = setup();
        let interaction = WindowInteraction::new(bridge.clone());
        let prompt = SecretPrompt::new("t", "TOTP code").with_kind(SecretKind::Totp);

        let (secret, _) = tokio::join!(interaction.ask_secret(prompt), async {
            let id = sink.first_prompt().await;
            bridge
                .answer(
                    id,
                    PromptAnswer::Secret {
                        value: SecretText::new("123456"),
                    },
                )
                .unwrap();
        });

        assert_eq!(secret.unwrap().expose_secret(), "123456");
        assert!(matches!(
            &sink.events()[0],
            UiEvent::Prompt {
                prompt: PromptRequest::Secret {
                    kind: SecretKind::Totp,
                    ..
                }
            }
        ));
        // The question is closed, not withdrawn.
        assert_eq!(sink.events().len(), 1);
    }

    #[tokio::test]
    async fn a_cancelled_question_is_cancelled() {
        let (sink, bridge) = setup();
        let interaction = WindowInteraction::new(bridge.clone());

        let (answer, _) = tokio::join!(interaction.confirm(ConfirmPrompt::new("t", "d")), async {
            let id = sink.first_prompt().await;
            bridge.answer(id, PromptAnswer::Cancel).unwrap();
        });

        assert!(matches!(answer, Err(InteractionError::Cancelled)));
    }

    #[tokio::test]
    async fn an_answer_that_does_not_fit_is_refused_and_the_question_stays_open() {
        let (sink, bridge) = setup();
        let interaction = WindowInteraction::new(bridge.clone());
        let prompt = ChoicePrompt::new("t", "d", ["a", "b"]);

        let (answer, _) = tokio::join!(interaction.choose(&prompt), async {
            let id = sink.first_prompt().await;
            assert_eq!(
                bridge.answer(id, PromptAnswer::Confirm { accepted: true }),
                Err(AnswerError::Mismatch)
            );
            assert_eq!(
                bridge.answer(id, PromptAnswer::Choice { index: 2 }),
                Err(AnswerError::Mismatch)
            );
            bridge
                .answer(id, PromptAnswer::Choice { index: 1 })
                .unwrap();
        });

        assert_eq!(answer.unwrap(), 1);
    }

    #[test]
    fn an_unknown_question_is_refused() {
        let (_, bridge) = setup();

        assert_eq!(
            bridge.answer(42, PromptAnswer::Cancel),
            Err(AnswerError::Unknown)
        );
    }

    #[tokio::test]
    async fn a_dropped_flow_withdraws_its_question() {
        let (sink, bridge) = setup();
        let interaction = WindowInteraction::new(bridge.clone());

        {
            let ask = interaction.confirm(ConfirmPrompt::new("t", "d"));
            let mut ask = std::pin::pin!(ask);
            // Poll once so the question is shown, then drop the flow.
            let _ = futures_poll_once(ask.as_mut()).await;
        }

        let events = sink.events();
        assert!(matches!(events.last(), Some(UiEvent::Withdraw { .. })));
        assert_eq!(
            bridge.answer(1, PromptAnswer::Cancel),
            Err(AnswerError::Unknown)
        );
    }

    async fn futures_poll_once<F: std::future::Future + Unpin>(f: F) -> Option<F::Output> {
        let mut f = f;
        std::future::poll_fn(|cx| match std::pin::Pin::new(&mut f).poll(cx) {
            std::task::Poll::Ready(v) => std::task::Poll::Ready(Some(v)),
            std::task::Poll::Pending => std::task::Poll::Ready(None),
        })
        .await
    }

    #[tokio::test]
    async fn closing_the_window_cancels_every_question() {
        let (sink, bridge) = setup();
        let interaction = WindowInteraction::new(bridge.clone());

        let (answer, _) = tokio::join!(
            interaction.ask_secret(SecretPrompt::new("t", "Password")),
            async {
                sink.first_prompt().await;
                bridge.cancel_all();
            }
        );

        assert!(matches!(answer, Err(InteractionError::Cancelled)));
    }

    #[tokio::test]
    async fn notices_reach_the_window() {
        let (sink, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());

        notifier
            .notify(&UserNotice::info("Touch your security key"))
            .await
            .unwrap();
        bridge.clear_notices();

        let events = sink.events();
        assert!(
            matches!(&events[0], UiEvent::Notice { notice } if notice.message.contains("Touch"))
        );
        assert_eq!(events[1], UiEvent::ClearNotices);
    }

    #[tokio::test]
    async fn giving_up_on_a_notice_ends_the_wait() {
        let (sink, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());
        notifier
            .notify(&UserNotice::info("Touch your security key").awaiting_action())
            .await
            .unwrap();
        assert!(matches!(&sink.events()[0], UiEvent::Notice { notice } if notice.cancellable));

        let id = notice_id(&sink, 0);

        tokio::join!(notifier.dismissed(), async {
            tokio::task::yield_now().await;
            bridge.cancel_notice(id);
        });
    }

    fn notice_id(sink: &FakeSink, at: usize) -> NoticeId {
        sink.events()
            .iter()
            .filter_map(|e| match e {
                UiEvent::Notice { notice } => Some(notice.id),
                _ => None,
            })
            .nth(at)
            .unwrap()
    }

    #[tokio::test]
    async fn a_cancel_before_the_wait_starts_is_not_lost() {
        let (sink, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());
        notifier
            .notify(&UserNotice::info("Touch").awaiting_action())
            .await
            .unwrap();

        bridge.cancel_notice(notice_id(&sink, 0));

        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(200), notifier.dismissed()).await;
        assert!(waited.is_ok());

        // The cancel was consumed: another wait stays pending until a new notice is cancelled.
        let again =
            tokio::time::timeout(std::time::Duration::from_millis(100), notifier.dismissed()).await;
        assert!(again.is_err());
    }

    #[tokio::test]
    async fn a_wait_started_before_the_notice_still_ends_with_its_cancel() {
        let (sink, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());

        // The webauthn flow starts waiting before the key asks for a touch.
        tokio::join!(notifier.dismissed(), async {
            tokio::task::yield_now().await;
            notifier
                .notify(&UserNotice::info("Touch").awaiting_action())
                .await
                .unwrap();
            bridge.cancel_notice(notice_id(&sink, 0));
        });
    }

    #[tokio::test]
    async fn cancelling_one_notice_leaves_the_other_flow_waiting() {
        let (sink, bridge) = setup();
        let a = WindowNotifier::new(bridge.clone());
        let b = WindowNotifier::new(bridge.clone());
        for n in [&a, &b] {
            n.notify(&UserNotice::info("Touch").awaiting_action())
                .await
                .unwrap();
        }

        bridge.cancel_notice(notice_id(&sink, 0));

        let wait = std::time::Duration::from_millis(50);
        assert!(tokio::time::timeout(wait, a.dismissed()).await.is_ok());
        assert!(tokio::time::timeout(wait, b.dismissed()).await.is_err());
    }

    #[tokio::test]
    async fn an_old_cancel_does_not_cancel_the_next_notice() {
        let (sink, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());
        let touch = UserNotice::info("Touch").awaiting_action();
        notifier.notify(&touch).await.unwrap();
        bridge.cancel_notice(notice_id(&sink, 0));
        notifier.notify(&touch).await.unwrap();

        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(50), notifier.dismissed()).await;
        assert!(waited.is_err());
    }

    #[tokio::test]
    async fn a_click_when_nothing_waits_is_forgotten() {
        let (_, bridge) = setup();
        let notifier = WindowNotifier::new(bridge.clone());

        // Nobody waits, so nothing is remembered for the next wait.
        bridge.cancel_notice(99);
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(20), notifier.dismissed()).await;

        assert!(waited.is_err());
    }
}
