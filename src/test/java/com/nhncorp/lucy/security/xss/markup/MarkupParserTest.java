package com.nhncorp.lucy.security.xss.markup;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

public class MarkupParserTest {
	@Test
	public void testNull() throws IOException {
		Assert.assertNull(MarkupParser.parse(null));
		Assert.assertEquals("", MarkupParser.toString(null));
		Assert.assertNotNull(MarkupParser.toString(new ArrayList()));
	}
}
