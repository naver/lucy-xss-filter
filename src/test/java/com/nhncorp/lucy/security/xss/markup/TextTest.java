/**
 * 
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author nhn
 *
 */
public class TextTest {
	/**
	 * Test method for {@link com.nhncorp.lucy.security.xss.markup.Text#serialize(java.io.Writer)}.
	 */
	@Test
	public void testSerialize1() throws IOException {
		Text t = new Text("test");
		try {
			t.serialize(null);
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

	@Test
	public void testSerialize2() throws IOException {
		try {
			Text t = new Text("        <");
			t.serialize(new PrintWriter(new OutputStreamWriter(System.out)));
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

	@Test
	public void testSerialize3() throws IOException {
		try {
			Text t = new Text("           >");
			t.serialize(new PrintWriter(new OutputStreamWriter(System.out)));
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

	@Test
	public void testSerialize4() throws IOException {
		try {
			Text t = new Text(null);
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}

}
