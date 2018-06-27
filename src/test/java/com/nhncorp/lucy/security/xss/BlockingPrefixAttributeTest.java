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
package com.nhncorp.lucy.security.xss;

import static junit.framework.Assert.*;

import org.junit.Test;

/**
 * @author nbp
 */
public class BlockingPrefixAttributeTest {
	@Test
	public void testBlockingPrefix() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String clean = filter.doFilter("<naverxx onmouseover=\"alert('kkk');\"></naverxx>");
		String expected = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><blocking_naverxx></blocking_naverxx>";
		assertEquals(expected, clean);

		String clean2 = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><blocking_iframe></blocking_iframe>";
		assertEquals(expected2, clean2);
	}

	@Test
	public void testATagStyleAttrExclusion() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String clean = filter.doFilter("<a href=\"악성페이지URL\" style=\"display: block; z-index: 100000; opacity: 0.5;position: fixed; top: 0px; left: 0; width: 1000000px; height: 100000px;background-color: red;\"> </a>");
		String expected = "<a href=http style=color> </a>";
		assertEquals(expected, clean);

		XssSaxFilter saxfilter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml");
		String saxclean = saxfilter.doFilter("<a href=\"악성페이지URL\" style=\"display: block; z-index: 100000; opacity: 0.5;position: fixed; top: 0px; left: 0; width: 1000000px; height: 100000px;background-color: red;\"> </a>");
		String saxexpected = "<a href=http style=color> </a>";
		assertEquals(saxexpected, saxclean);

		XssFilter filter2 = XssFilter.getInstance();
		String clean2 = filter2.doFilter("<a href=\"악성페이지URL\" style=\"display: block;\"><span style=\"display: block;\"></span></a>");
		String expected2= "<!-- Not Allowed Attribute Filtered ( style=\"display: block;\") --><a href=\"악성페이지URL\"><span style=\"display: block;\"></span></a>";
		assertEquals(expected2, clean2);

		XssSaxFilter saxfilter2 = XssSaxFilter.getInstance();
		String saxclean2 = saxfilter2.doFilter("<a href=\"악성페이지URL\" style=\"display: block;\"><span style=\"display: block;\"></span></a>");
		String saxexpected2 = "<!-- Not Allowed Attribute Filtered ( style=\"display: block;\") --><a href=\"악성페이지URL\"><span style=\"display: block;\"></span></a>";
		assertEquals(saxexpected2, saxclean2);
	}

	@Test
	public void testSaxBlockingPrefix() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		String clean = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xiframe></xiframe>";
		assertEquals(expected, clean);
	}

	@Test
	public void testSaxBlockingPrefix2() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		String clean2 = filter.doFilter("<naverxx onmouseover=\"alert('kkk');\"></naverxx>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xnaverxx></xnaverxx>";
		assertEquals(expected2, clean2);
	}
}
