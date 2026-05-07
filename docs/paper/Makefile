LATEX  ?= pdflatex
BIBTEX ?= bibtex
TEX     = paper.tex
PDF     = paper.pdf

.PHONY: all clean distclean

all: $(PDF)

$(PDF): $(TEX) refs.bib
	$(LATEX)  -interaction=nonstopmode $(TEX)
	$(BIBTEX) $(basename $(TEX))
	$(LATEX)  -interaction=nonstopmode $(TEX)
	$(LATEX)  -interaction=nonstopmode $(TEX)

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.synctex.gz *.fls *.fdb_latexmk

distclean: clean
	rm -f $(PDF)
