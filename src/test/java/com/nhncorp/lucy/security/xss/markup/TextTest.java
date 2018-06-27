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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import org.junit.Test;

public class TextTest {
	/**
	 * Test method for {@link com.nhncorp.lucy.security.xss.markup.Text#serialize(java.io.Writer)}.
	 */
	@Test
	public void testSerialize1() throws IOException {
		Text text = new Text("test");
		text.serialize(null);
	}

	@Test
	public void testSerialize2() throws IOException {
		Text text = new Text("        <");
		text.serialize(new PrintWriter(new OutputStreamWriter(System.out)));
	}

	@Test
	public void testSerialize3() throws IOException {
		Text text = new Text("           >");
		text.serialize(new PrintWriter(new OutputStreamWriter(System.out)));
	}

	@Test
	public void testSerialize4() throws IOException {
		Text text = new Text(null);
		text.serialize(new PrintWriter(new OutputStreamWriter(System.out)));
	}
}
