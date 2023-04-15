#
# If pwd == draft-name, will not need to touch this

DIRNAME := $(shell basename $(CURDIR))

VERSION = 00
DOCNAME = $(DIRNAME)

all: $(DOCNAME)-$(VERSION).txt $(DOCNAME)-$(VERSION).html

$(DOCNAME)-$(VERSION).txt: $(DOCNAME)-$(VERSION).xml
	@xml2rfc --text -o $@ $<
	@sed -e '1s/^/```\n/' $@ | sed '$$ s/$$/\n```/' > README.md

$(DOCNAME)-$(VERSION).html: $(DOCNAME)-$(VERSION).xml
	@xml2rfc --html -o $@ $<

$(DOCNAME)-$(VERSION).xml: $(DOCNAME).md
	@sed 's/@DOCNAME@/$(DOCNAME)-$(VERSION)/g' $< | mmark > $@

clean:
	@rm -f $(DOCNAME)-$(VERSION).txt $(DOCNAME)-$(VERSION).html $(DOCNAME)-$(VERSION).xml

diff:	$(DOCNAME)-$(VERSION).txt
	rfcdiff $(DOCNAME)-$(shell echo ${VERSION} - 1 | bc).txt $(DOCNAME)-$(VERSION).txt
