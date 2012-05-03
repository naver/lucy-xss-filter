/*
 * @(#)EtcTest.java $version 2012. 4. 24.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author nbp
 */
public class EtcTest {

	@Ignore
	@Test
	public void Temp() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<img src=http://%a.com%0bonerror=\"alert(document.cookie\">";
		String expected = "<div><video></video></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Ignore
	@Test
	public void Temp2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<img src=\"aaa%0bonerror=alert(111)>";
		String expected = "<div><video></video></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Ignore
	@Test
	public void hrefPatternTestMailBackup() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-href-mail.xml");
		String dirty = "<a href=\"javascript:mUtil.viewEmbed('29522','http://jeokhojae.netorage.com:8711/harddisk/user/K00113.wmv','640','450');\"><span nid=\"naver_embed_29522\"><img src=http://static.naver.com/mail4/img_noti_embed_1.gif></img></span></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternTestMail() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-href-mail.xml");
		String dirty = "<a href=\"javascript:mUtil.viewEmbed('29522','http://jeokhojae.netorage.com:8711/harddisk/user/K00113.wmv','640','450');\"><img src=http://static.naver.com/mail4/img_noti_embed_1.gif></img></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternNormalMail() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-href-mail.xml");
		String dirty = "<a href=\"http://www.naver.com/\"></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternNormalButNoProtocolMail() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-href-mail.xml");
		String dirty = "<a href=\"www.naver.com/\"></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternJavascriptMail() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-href-mail.xml");
		String dirty = "<a href=\"javascript:alert(1);\"></a>";
		String expected = "<!-- Not Allowed Attribute Filtered ( href=\"javascript:alert(1);\") --><a></a>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternTest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<a href=\"javascript:mUtil.viewEmbed('29522','http://jeokhojae.netorage.com:8711/harddisk/user/K00113.wmv','640','450');\"><img src=http://static.naver.com/mail4/img_noti_embed_1.gif></img></a>";
		String expected = "<!-- Not Allowed Attribute Filtered ( href=\"javascript:mUtil.viewEmbed('29522','http://jeokhojae.netorage.com:8711/harddisk/user/K00113.wmv','640','450');\") --><a><img src=http://static.naver.com/mail4/img_noti_embed_1.gif></img></a>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternNormal() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<a href=\"http://www.naver.com/\"></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternNormalButNoProtocol() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<a href=\"www.naver.com/\"></a>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hrefPatternJavascript() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<a href=\"javascript:alert(1);\"></a>";
		String expected = "<!-- Not Allowed Attribute Filtered ( href=\"javascript:alert(1);\") --><a></a>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Ignore
	@Test
	public void hexCodeAttackPaatern1() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "half\"><img src=''%0conerror=alert(document.cookie) alt=\"&page=1&forumno=7";
		String expected = "half\"&gt;<!-- Not Allowed Attribute Filtered --><img src='' alt=\"&page=1&forumno=7>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void hexCodeAttackPaatern2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "page=1\"><img src=http://a.com\fonerror=\"alert(document.cookie)"; // \f => %0b (form feed)
		String expected = "page=1\"&gt;<!-- Not Allowed Attribute Filtered ( onerror=\"alert(document.cookie)) --><img src=http://a.com>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
}
