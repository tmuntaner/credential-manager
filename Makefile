NAME = c9s
VERSION = 0.1.0

clean:
	rm -rf package/obs/*.tar.bz2
	rm -rf $(NAME)-$(VERSION)/

dist: clean
	@mkdir -p $(NAME)-$(VERSION)/
	@cp -r src $(NAME)-$(VERSION)/
	@cp -r Cargo.* $(NAME)-$(VERSION)/
	tar cfvj package/obs/$(NAME)-$(VERSION).tar.bz2 $(NAME)-$(VERSION)/
	rm -rf $(NAME)-$(VERSION)/

	cargo vendor
	tar cfvj package/obs/vendor.tar.bz2 vendor/
	rm -rf vendor/
