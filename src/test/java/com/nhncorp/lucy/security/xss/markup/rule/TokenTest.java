/*
 * @(#) TokenTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class TokenTest {
	@Test
	public void test() {
		Token t = new Token(null);
		t.setValue(new CharArraySegment(new char[] {'a', 'b', 'c', 'd'}, 0, 1));
		Assert.assertEquals("", t.getName());

		t.addChild(null);
		t.addChild(new Token("test0"));
		t.addChildren(null);

		Assert.assertNull(t.getChild(0));

		List<Token> list = new ArrayList<Token>();
		list.add(new Token("test1"));
		list.add(new Token("test2"));
		list.add(new Token("test3"));
		t.addChildren(list);
		t.setValue(null);

		Assert.assertNull(t.getChild(0));
		Assert.assertNull(t.getChild("none"));
	}
}
