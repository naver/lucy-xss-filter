/*
 * @(#)MailBlockingPrefixTest.java $version Mar 6, 2013
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

import junit.framework.Assert;

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
		Assert.assertEquals(expected, clean);
		
		String clean2 = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><blocking_iframe></blocking_iframe>";
		Assert.assertEquals(expected2, clean2);
	}
	
	@Test
	public void testATagStyleAttrExclusion() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String clean = filter.doFilter("<a href=\"악성페이지URL\" style=\"display: block; z-index: 100000; opacity: 0.5;position: fixed; top: 0px; left: 0; width: 1000000px; height: 100000px;background-color: red;\"> </a>");
		String expected = "<a href=http style=color> </a>";
		Assert.assertEquals(expected, clean);
		
		XssSaxFilter saxfilter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml");
		String saxclean = saxfilter.doFilter("<a href=\"악성페이지URL\" style=\"display: block; z-index: 100000; opacity: 0.5;position: fixed; top: 0px; left: 0; width: 1000000px; height: 100000px;background-color: red;\"> </a>");
		String saxexpected = "<a href=http style=color> </a>";
		Assert.assertEquals(saxexpected, saxclean);
		
		XssFilter filter2 = XssFilter.getInstance();
		String clean2 = filter2.doFilter("<a href=\"악성페이지URL\" style=\"display: block;\"><span style=\"display: block;\"></span></a>");
		String expected2= "<!-- Not Allowed Attribute Filtered ( style=\"display: block;\") --><a href=\"악성페이지URL\"><span style=\"display: block;\"></span></a>";
		Assert.assertEquals(expected2, clean2);
		
		XssSaxFilter saxfilter2 = XssSaxFilter.getInstance();
		String saxclean2 = saxfilter2.doFilter("<a href=\"악성페이지URL\" style=\"display: block;\"><span style=\"display: block;\"></span></a>");
		String saxexpected2 = "<!-- Not Allowed Attribute Filtered ( style=\"display: block;\") --><a href=\"악성페이지URL\"><span style=\"display: block;\"></span></a>";
		Assert.assertEquals(saxexpected2, saxclean2);
	}
	 
	
	@Test
	public void testSAXBlockingPrefix() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		String clean = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xiframe></xiframe>";
		Assert.assertEquals(expected, clean);
		
	}
	
	
	@Test
	public void testSAXBlockingPrefix2() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		
		String clean2 = filter.doFilter("<naverxx onmouseover=\"alert('kkk');\"></naverxx>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xnaverxx></xnaverxx>";
		Assert.assertEquals(expected2, clean2);
	}

}
