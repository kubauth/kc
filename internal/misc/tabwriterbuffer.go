package misc

import (
	"fmt"
	"text/tabwriter"
)

type TabWriterBuffer interface {
	Add(title string, tag string, value interface{})
	EndOfLine()
}

type tabWriterBuffer struct {
	tabWriter  *tabwriter.Writer
	head       string
	tags       string
	values     []interface{}
	firstLine  bool
	firstCell  bool
	tagByTitle map[string]string
}

func NewTabWriterBuffer(writer *tabwriter.Writer) TabWriterBuffer {
	t := &tabWriterBuffer{
		tabWriter:  writer,
		head:       "",
		tags:       "",
		values:     make([]interface{}, 0, 20),
		firstLine:  true,
		firstCell:  true,
		tagByTitle: make(map[string]string),
	}
	return t
}

func (t *tabWriterBuffer) Add(title string, tag string, value interface{}) {
	if t.firstLine {
		if !t.firstCell {
			t.head += "\t"
			t.tags += "\t"
		}
		t.head += title
		t.tags += tag
		t.tagByTitle[title] = tag
	}
	if t.tagByTitle[title] != tag {
		panic(fmt.Sprintf("Different tag ('%s'!='%s') for %s", t.tagByTitle[title], tag, title))
	}
	t.values = append(t.values, value)
	t.firstCell = false
}

func (t *tabWriterBuffer) EndOfLine() {
	if t.firstLine {
		t.head += "\n"
		t.tags += "\n"
		_, _ = fmt.Fprintf(t.tabWriter, t.head)
	}
	_, _ = fmt.Fprintf(t.tabWriter, t.tags, t.values...)
	t.firstLine = false
	t.firstCell = true
	t.values = make([]interface{}, 0, 20)
}
