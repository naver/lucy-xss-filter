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
package com.nhncorp.lucy.security.xss.config;

import static junit.framework.Assert.*;

import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

import com.nhncorp.lucy.security.xss.markup.Attribute;

public class AttributeRuleTest {
	@Test
	public void testNull() throws Exception {
		AttributeRule rule = new AttributeRule(null, false);

		assertEquals("", rule.getName());
		assertEquals(false, rule.isDisabled());
		rule.setDisabled(true);
		rule.checkDisabled(new Attribute(""));

		AttributeRule a1 = new AttributeRule("", false);
		assertEquals("", a1.getName());

		a1.addNotAllowedPattern(null);
		a1.addNotAllowedPatterns(new ArrayList());

		a1.addAllowedPattern(null);
		a1.addAllowedPatters(new ArrayList());
	}
}
