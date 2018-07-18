/*
 *	Copyright 2014 Naver Corp.
 *
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */
package com.nhncorp.lucy.security.xss.markup;

import static junit.framework.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;

public class MarkupParserTest {
	@Test
	public void testToStringNullEmpty() throws IOException {
		assertEquals("", MarkupParser.toString(null));
		assertEquals("", MarkupParser.toString(new ArrayList<Content>()));
	}

	@Test
	public void testParseNullEmpty() throws IOException {
		assertNull(MarkupParser.parse(null));
		assertNull(MarkupParser.parse(""));
	}

	@Test
	public void testParsePara() {
		// given
		String html = "<p>test</p>";

		// when
		Collection<Content> contents = MarkupParser.parse(html);

		// then
		Element para = (Element) contents.iterator().next();
		assertPTag(para, "test");
	}

	@Test
	public void testParseParaUnmatched() {
		// given
		String html = "</p>test<p>";

		// when
		Collection<Content> contents = MarkupParser.parse(html);

		// then
		Iterator<Content> itr = contents.iterator();

		Text text1 = (Text) itr.next();
		assertEquals("&lt;/p&gt;", text1.toString());

		Text text2 = (Text) itr.next();
		assertEquals("test", text2.toString());

		Element para = (Element) itr.next();
		assertEquals("p", para.getName());
		assertNull(para.getElements());
		assertFalse(para.isClosed());
		assertFalse(para.isStartClosed());
	}

	@Test
	public void testParseConditionalComment() {
		String html = "<p>"
				+ "<!--[if !supportLists]>"
				+ "<p>test</p>"
				+ "<![endif]-->"
				+ "</p>";

		// when
		Collection<Content> contents = MarkupParser.parse(html);

		// then
		Element parent = (Element) contents.iterator().next();
		assertPTag(parent, true);

		IEHackExtensionElement comment = (IEHackExtensionElement) parent.getElements().iterator().next();
		assertEquals("<!--[if !supportLists]>", comment.getName());
		assertTrue(comment.isClosed());
		assertFalse(comment.isStartClosed());

		Element para = comment.getElements().iterator().next();
		assertPTag(para, "test");
	}

	@Test
	public void testParseConditionalCommentUnmatched() {
		String html = "<p><!--[if !supportLists]></p>"
				+ "<p>test</p>"
				+ "<p><![endif]--></p>";

		// when
		Collection<Content> contents = MarkupParser.parse(html);

		// then
		Iterator<Content> itr = contents.iterator();

		Element para1 = (Element) itr.next();
		assertPTag(para1, true);

		IEHackExtensionElement comment = (IEHackExtensionElement) para1.getContents().iterator().next();
		assertEquals("<!--[if !supportLists]>", comment.getName());
		assertFalse(comment.isClosed());
		assertFalse(comment.isStartClosed());

		Element para2 = (Element) itr.next();
		assertPTag(para2, "test");

		Element para3 = (Element) itr.next();
		assertPTag(para3, "&lt;![endif]--&gt;");
	}

	private void assertPTag(Element para, String content) {
		assertPTag(para, true);
		Text text = (Text) para.getContents().iterator().next();
		assertEquals(content, text.toString());
	}

	private void assertPTag(Element para,  boolean closed) {
		assertEquals("p", para.getName());
		assertEquals(closed, para.isClosed());
		assertFalse(para.isStartClosed());
	}
}
