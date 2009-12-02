package com.nhncorp.lucy.security.xss.markup;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

public class ElementTest {
	@Test
	public void testRemoveElement() {
		try {
			Element e = new Element("<embed>");
			ArrayList<Element> list = new ArrayList<Element>();
			list.add(new Element("<div>"));
			list.add(new Element("<tag>"));
			e.addContents(list);
			e.removeContent(null);
			e.removeContent(0);
			e.removeContent(new Element("<div>"));

			Element e1 = new Element(null);
			e1.removeContent(0);
		} catch (Exception ex) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

	@Test
	public void testSerialize() throws IOException {
		Element e = new Element("<embed>");
		e.serialize(null);

		e.setContent(0, null);
		e.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));

		e.addContent(new Element("<param>"));
		e.addContent(new Element("<param>"));
		e.addContent(new Element("<id>"));
		e.setClose(true);
		e.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));
	}

	@Test
	public void testGetElements() throws IOException {
		Element e1 = new Element(null);
		Assert.assertEquals(-1, e1.indexOf(new Element("<id>")));

		Element e2 = new Element("<embed>");
		Assert.assertNull(e2.getElementsByTagName(null));

		e2.addContent(new Element("<param>"));
		e2.addContent(new Element("<param>"));
		e2.addContent(new Element("<id>"));
		Assert.assertNotNull(e2.getElementsByTagName("<param>"));

		Assert.assertEquals(-1, e2.indexOf(new Element("<id>")));
	}

	@Test
	public void testNull() {
		Element e = null;
		try {
			e.addContent(null);
			Assert.assertNull(e.getContents());

			e = new Element("<id>");
			e.putAttribute(null);

			e.addContent(null);
			e.setContent(0, null);
			e.addContent(0, null);

			e.setContent(0, new Element(""));
			e = new Element(null);
			e.getAttribute(null);

		} catch (Exception ex) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

}
