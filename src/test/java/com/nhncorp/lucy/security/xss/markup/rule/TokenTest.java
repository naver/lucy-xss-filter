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
package com.nhncorp.lucy.security.xss.markup.rule;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class TokenTest {
	@Test
	public void test() {
		Token token = new Token(null);
		token.setValue(new CharArraySegment(new char[] {'a', 'b', 'c', 'd'}, 0, 1));
		assertEquals("", token.getName());

		token.addChild(null);
		token.addChild(new Token("test0"));
		token.addChildren(null);
		assertNull(token.getChild(0));

		List<Token> list = new ArrayList<Token>();
		list.add(new Token("test1"));
		list.add(new Token("test2"));
		list.add(new Token("test3"));
		token.addChildren(list);
		token.setValue(null);
		assertNull(token.getChild(0));
		assertNull(token.getChild("none"));
	}
}
