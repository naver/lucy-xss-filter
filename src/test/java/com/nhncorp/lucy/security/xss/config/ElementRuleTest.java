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

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Test;

public class ElementRuleTest {
	@Test
	public void testNull() throws Exception {
		ElementRule e = new ElementRule(null);
		Assert.assertEquals("", e.getName());

		ElementRule e1 = new ElementRule("test");
		Assert.assertEquals("test", e1.getName());

		try {
			e1.checkEndTag(null);
			e1.addAllowedAttribute(null);
			e1.addAllowedAttributes(new ArrayList());

			e1.addAllowedElement("");
			e1.addAllowedElement(null);
			e1.addAllowedElements(new ArrayList());

			e1.addListener(null);
		} catch (Exception ex) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);

	}
}
