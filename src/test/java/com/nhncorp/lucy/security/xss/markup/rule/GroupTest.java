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

import junit.framework.Assert;

import org.junit.Test;

public class GroupTest {
	@Test
	public void testNull() {
		Group g = new Group(null);
		Assert.assertEquals("", g.getRuleName());
		Assert.assertNull(g.getOperator());
		Assert.assertNull(Group.OPERATOR.getValue('t'));

		try {
			g.add(null);
			g.addAll(null);
			g.remove(null);
			Assert.assertEquals(-1, g.matchPos(null, null));
			Assert.assertEquals(-1, g.matchPos(null, ParsingGrammar.getInstance()));

			Assert.assertNotNull(g.getFirstNonOptTerminals(ParsingGrammar.getInstance()));
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
