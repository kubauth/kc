/*
Copyright 2025 Kubotal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
