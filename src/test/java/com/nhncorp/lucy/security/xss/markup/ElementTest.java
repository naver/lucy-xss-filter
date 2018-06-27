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

import static org.junit.Assert.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;

import junit.framework.Assert;

import org.junit.Test;

public class ElementTest {
	@Test
	public void testRemoveElement() {
		List<Element> list = new ArrayList<Element>();
		list.add(new Element("<div>"));
		list.add(new Element("<tag>"));

		Element elem = new Element("<embed>");
		elem.addContents(list);

		elem.removeContent(null);
		elem.removeContent(0);
		elem.removeContent(new Element("<div>"));
		Element e1 = new Element(null);
		e1.removeContent(0);
	}

	@Test
	public void testSerialize() throws IOException {
		Element elem = new Element("<embed>");
		elem.serialize(null);

		elem.setContent(0, null);
		elem.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));

		elem.addContent(new Element("<param>"));
		elem.addContent(new Element("<param>"));
		elem.addContent(new Element("<id>"));
		elem.setClose(true);
		elem.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));
	}

	@Test
	public void testGetElements() throws IOException {
		Element e1 = new Element(null);
		assertEquals(-1, e1.indexOf(new Element("<id>")));

		Element e2 = new Element("<embed>");
		Assert.assertNull(e2.getElementsByTagName(null));

		e2.addContent(new Element("<param>"));
		e2.addContent(new Element("<param>"));
		e2.addContent(new Element("<id>"));
		assertNotNull(e2.getElementsByTagName("<param>"));

		assertEquals(-1, e2.indexOf(new Element("<id>")));
	}

	@Test
	public void testNull() {
		Element elem = new Element("<id>");
		elem.putAttribute(null);
		elem.addContent(null);
		elem.addContent(0, null);

		elem = new Element(null);
		elem.getAttribute(null);
	}

	@Test(expected = IndexOutOfBoundsException.class)
	public void testInvalidIndex() {
		Element elem = new Element("<id>");
		elem.setContent(0, new Element(""));
		assertTrue(elem.getContents().isEmpty());
	}
}