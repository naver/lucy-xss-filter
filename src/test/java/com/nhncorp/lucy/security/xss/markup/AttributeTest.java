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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import junit.framework.Assert;

import org.junit.Test;

public class AttributeTest {
	@Test
	public void test() {
		Attribute attr = new Attribute(null, null);
		Assert.assertEquals("", attr.getValue());
		Assert.assertTrue(attr.isMinimized());

		attr.setValue("test");
		Assert.assertFalse(attr.isMinimized());
	}

	@Test
	public void testSerialize() {
		try {
			Attribute attr = new Attribute("test", " <test>");
			attr.serialize(null);
			attr.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));

			attr.setValue(null);
			attr.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));
		} catch (IOException ioe) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
