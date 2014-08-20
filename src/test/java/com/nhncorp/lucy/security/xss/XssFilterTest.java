/*
 * @(#) XssFilterTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.log4j.MDC;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * {@link XssFilter} 기능 점검을 위한 테스트 코드.
 *
 * 공격적인 코드와 완전하지 않은 HTML을 필터링 하는지와, 정상적인 HTML을 원형 그대로 보존하는지 검사한다.
 *
 * @author Web Platform Development Team
 */
public class XssFilterTest extends XssFilterTestCase {
	private static final String DIRTY_CODES_FILE = "xss-dirtycodes.txt";
	private static final String INVALID_HTML_FILES[] = {"xss-invalid1.html", "xss-invalid2.html", "xss-invalid3.html"};
	private static final String NORMAL_HTML_FILES[] = {"xss-normal1.html"};
	private static final String NORMAL_HTML_FILE = "xss-normal1.html";
	private static final String INVALID_HTML_FILE = "xss-invalid1.html";
	
	private static final String[] targetString = {"<script></script>", "<body text='test'><p>Hello</p></body>", "<img src='script:/lereve/lelogo.gif' width='700'>"};
	private static final String[] expectedString = {"<!-- Not Allowed Tag Filtered -->&lt;script&gt;&lt;/script&gt;", "<!-- Not Allowed Tag Filtered -->&lt;body text='test'&gt;<p>Hello</p>&lt;/body&gt;", "<!-- Not Allowed Attribute Filtered ( src='script:/lereve/lelogo.gif') --><img width='700'>"};
	
	private static final String[] configFile = {"lucy-xss-superset.xml","lucy-xss-superset.xml", "lucy-xss-blog-removetag.xml"};
	private static final String[] targetStringOnOtherConfig = {"<img src='script:/lereve/lelogo.gif' width='700'>", "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->", "<html><head></head><body><p>Hello</p></body>"};
	private static final String[] expectedStringOnOtherConfig = {"<!-- Not Allowed Attribute Filtered ( src='script:/lereve/lelogo.gif') --><img width='700'>", "<!--[if !supportMisalignedColumns]><h1>Hello</h1><![endif]-->", "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><p>Hello</p>"};

	@Test
	// 정상적인 HTML 페이지를 통과 시키는지 검사한다.(필터링 전후가 동일하면 정상)
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		for (String valid : readString(NORMAL_HTML_FILES)) {
			String clean = filter.doFilter(valid);
			Assert.assertTrue("\n" + valid + "\n" + clean, valid.equals(clean));
		}
	}

	@Ignore
	@Test
	// JavaScript와 같은 공격적인 코드를 필터링 하는지 검사한다.(필터링 전후가 틀려야 정상)
	public void testDirtyCodeFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		for (String line : readLines(DIRTY_CODES_FILE)) {
			String clean = filter.doFilter(line);
			Assert.assertFalse("\n" + line + "\n" + clean, line.equals(clean));
		}
	}

	@Test
	// 시스템을 공격하는 코드를 필터링 하는지 검사한다.(필터링 전후가 틀려야 정상)
	public void testCrackCodeFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		for (String invalid : readString(INVALID_HTML_FILES)) {
			String clean = filter.doFilter(invalid);
			System.out.println("clean : " + clean);
			Assert.assertFalse("\n" + invalid + "\n" + clean, invalid.equals(clean));
		}
	}

	public static void main(String[] args) throws XssFilterException {
		String dirty = "<link rel=\"stylesheet\" type=\"text/css\" href=\"http://daumucc.cafe24.com/nk1\">";
		System.out.println(XssFilter.getInstance().doFilter(dirty));
	}

	@Test
	// 설정 파일 명을 입력하지 않았을 때와 각각 다른 설정 파일을 로딩하였을 때에 제대로 필터링 하는지 검사한다.
	// (lucy-xss.xml과 lucy-xss2.xml의 필터링 결과가 틀려야 정상)
	public void testConfigutaionLoading() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		XssFilter sameFilter = XssFilter.getInstance("lucy-xss-superset.xml");
		XssFilter otherFilter = XssFilter.getInstance("lucy-xss.xml");

		String dirty = "<applet><!-- abc --></applet>";

		String clean = filter.doFilter(dirty);
		String sameClean = sameFilter.doFilter(dirty);
		String otherClean = otherFilter.doFilter(dirty);

		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		System.out.println("sameClean : " + sameClean);
		System.out.println("otherClean : " + otherClean);

		Assert.assertTrue("\n" + clean + "\n" + sameClean, clean.equals(sameClean));
		Assert.assertFalse("\n" + clean + "\n" + otherClean, clean.equals(otherClean));
	}

	@Test
	// White Url을 포함하지 않은 Embed 태그에 대한 보안 필터링 하는지 검사한다.
	public void testEmbedListener() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss3.xml");

		String dirty = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\">";
		String expected = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\" type=\"video/x-ms-wmv\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}

	@Test
	// White Url을 포함한 Embed 태그에 대한 보안 필터링 하는지 검사한다.
	public void testEmbedListenerWithWhiteUrl() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss3.xml");

		String dirty = "<EMBED src=\"http://play.tagstory.com/player/harisu.wmv\" width=\"425\" height=\"344\">";
		String expected = "<EMBED src=\"http://play.tagstory.com/player/harisu.wmv\" width=\"425\" height=\"344\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"all\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	// 중첩된 Object 태그에 대한 보안 필터링 하는지 검사한다.
	public void testObjectListener() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss3.xml");

		String dirty = readString("xss-dirtyobject.html");
		String expected = readString("xss-dirtyobject-expected.html");
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		//Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}

	@Test
	public void testNull() {
		XssFilter filter = XssFilter.getInstance();
		Assert.assertNotNull(filter.getConfig());
		Assert.assertEquals("", filter.doFilter(null));
		Assert.assertEquals("", filter.doFilter(null, null, null));
		Assert.assertNotNull(filter.doFilter("embeded", "param", "param"));
	}

	@Test
	//lucy-xss-superset.xml <notAllowedPattern><![CDATA[&[#\\%x]+[\da-fA-F][\da-fA-F]+]]></notAllowedPattern> 수정
	//그 결과 COLOR 색상표(#16진수)는 필터링하지 않는다.
	public void testSuperSetFix() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String clean = "<TABLE class=\"NHN_Layout_Main\" style=\"TABLE-LAYOUT: fixed\" cellSpacing=\"0\" cellPadding=\"0\" width=\"743\">" + "</TABLE>" + "<SPAN style=\"COLOR: #66cc99\"></SPAN>";
		String filtered = filter.doFilter(clean);
		Assert.assertEquals(clean, filtered);
	}

	@Test
	//EndTag가 없는 HTML이 입력으로 들어왔을 때 필터링한다. (WhiteList File의 Element 속성 EndTag 값이 true 인 경우)
	public void testEndTagFilter() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<p><FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">" + "<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">" + "<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT></FONT></P>";
		String clean = filter.doFilter(dirty);
		String unexpected = dirty;
		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		Assert.assertNotSame(unexpected, clean);
	}

	@Test
	//HTML5 적용된 브라우저에서 Base64 인코딩된 XSS 우회 공격을 필터링한다.
	public void testBase64DecodingTest() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-embed.xml");
		String dirty = "<embed src=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\">";
		String expected = "<!-- Not Allowed Attribute Filtered ( src=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\") --><embed invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		String dirty2 = "<object data=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\"></object>";
		String expected2 = "<!-- Not Allowed Attribute Filtered ( data=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\") --><object><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}

	@Test
	// Element Class의 setName Method와 removeAllAttributes Method를 테스트한다.
	// IMGLinstener에서 해당 메소드를 호출하여 IMG를 iframe으로 변경하고, IMG의 모든 속성을 제거한 후 원하는 속성으로 변경한다.
	public void testRemoveAllAttributesTest() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-cafe-child.xml");

		String dirty = "<IMG id=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv height=284 src=\"http://thumb.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe_player.jpg\" width=342 movietype=\"1\">";
		String expected = "<iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv?key=></iframe>";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));

		dirty = "<IMG></IMG>";
		expected = "<iframe></iframe>";
		String actual = filter.doFilter(dirty);
		Assert.assertEquals(expected, actual);

	}

	@Test
	public void testASCIICtrlChars() {
		// ASCIICtrl Chars : URL encoded %00 ~ %1F, %7F 이중 문제가 되는 것은 %00 뿐이다.
		XssFilter filter = XssFilter.getInstance();

		String dirty = URLDecoder.decode("%00");
		String expected = "\0";
		String clean = filter.doFilter(dirty);

		Assert.assertTrue(expected.equals(clean));

		String dirty2 = "aaa\0aaa";
		String expected2 = "aaa\0aaa";
		String clean2 = filter.doFilter(dirty2);

		Assert.assertTrue(expected2.equals(clean2));

		String dirty3 = "\0aaa\0\0aaa\0";
		String expected3 = "\0aaa\0\0aaa\0";
		String clean3 = filter.doFilter(dirty3);

		Assert.assertTrue(expected3.equals(clean3));

	}

	// startTag에서 공백 뒤에 오는 Close char '/' 를 attributeName으로 인식하는 오류 수정
	// e.g. <br />, <img src="aaaa" />
	// 공백 + /> 가 표준이므로 공백 없이 '/' char가 온 경우도 공백을 넣어서 리턴하도록 함.
	// e.g. <br/> -> <br />
	@Test
	public void testXHTMLStandard() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<br />";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(dirty,clean);

		String dirty2 = "<img src=\"aaaa\" />";
		String clean2 = filter.doFilter(dirty2);

		Assert.assertTrue(dirty2.equals(clean2));

		String dirty3 = "<br/>";
		String expected3 = "<br />";
		String clean3 = filter.doFilter(dirty3);
		Assert.assertTrue(expected3.equals(clean3));

		String dirty4 = "<img src=\"aaaa\"/>";
		String expected4 = "<img src=\"aaaa\" />";
		String clean4 = filter.doFilter(dirty4);

		Assert.assertTrue(expected4.equals(clean4));

		String dirty5 = "<p>" + "<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">" + "<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT>" + "<br />" + "</FONT>" + "</p>";

		String clean5 = filter.doFilter(dirty5);
		Assert.assertTrue(clean5.equals(dirty5));

		String dirty6 = "<img src=\"aaaa\" >";
		String expected6 = "<img src=\"aaaa\">";
		String clean6 = filter.doFilter(dirty6);

		Assert.assertTrue(expected6.equals(clean6));

	}

	@Test
	//VM 옵션 -Xss 128k 에서 overflow 발생하는 사례 / -Xss 256k or Defalut(512k) 옵션에서는 정상 작동
	public void testCafeHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-cafe-child.xml");
		for (String valid : readLines("StackOverFlowError_Sample.html")) {
			String clean = filter.doFilter(valid);
			//Assert.assertTrue("\n" + valid + "\n" + clean, valid.equals(clean));
		}
	}

	@Test
	//필터링된 Tag와 Attribute 입력에 Comment를 삽입하는 것은 옵션으로한다.
	//getInstance의 두번째 파라미터가 noComment를 설정할 수 있다.
	public void testNoCommentXSSFilter() {

		XssFilter filter = XssFilter.getInstance("lucy-xss5.xml", true);
		String dirty = "<embed src=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\"></embed>";
		String expected = "<embed></embed>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		String dirty2 = "<script></script>";
		String expected2 = "&lt;script&gt;&lt;/script&gt;";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}

	@Test
	//DOCTYPE과 xml 태그를 허용하도록한다.
	public void testDOCTYPEAndXMLELEMNT() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");

		String doctype = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">";
		String clean = filter.doFilter(doctype);
		Assert.assertEquals(doctype, clean);

		String xmltag = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		clean = filter.doFilter(xmltag);
		Assert.assertEquals(xmltag, clean);

		String xssElement = "<script></script>";
		String expected = "<blocking_script></blocking_script>";
		clean = filter.doFilter(xssElement);
		Assert.assertEquals(expected, clean);

	}

	@Test
	public void testOverrideIssue() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-body-test.xml");
		String testDirty = "<div><o:p><FONT face=\"맑은 고딕\">&nbsp;</FONT></o:p></div><span lang=EN-US>TEST</span>";
		String clean = filter.doFilter(testDirty);
		Assert.assertEquals(testDirty, clean);

		testDirty = "<p><newElement1></newElement1></p>";
		clean = filter.doFilter(testDirty);
		Assert.assertEquals(testDirty, clean);

		testDirty = "<body><embed></embed></body>";
		clean = filter.doFilter(testDirty);
		Assert.assertEquals(testDirty, clean);

		testDirty = "<a bordercolordark=b></a>";
		clean = filter.doFilter(testDirty);
		Assert.assertEquals(testDirty, clean);

	}

	@Test
	//IEHack을 허용한다.
	public void testIEHackTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-default.xml");
		String dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		//String dirty = "<!--[if gte mso 9]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String expected = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if !IE]><-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if !IE]>&lt;--&gt;";
		Assert.assertEquals(expected, clean);

		dirty = "<!--> <![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--&gt; &lt;![endif]-->";
		Assert.assertEquals(expected, clean);

	}

	@Test
	public void testIEHackTagOtherCase() {
		XssFilter xssFilter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !supportMisalignedColumns]--> <style> div { border:1px solid #f00; } </style><!--[endif]-->";
		String clean = xssFilter.doFilter(dirty);

		String Expected = "<!--[if !supportMisalignedColumns]> <style></style><![endif]-->";
		Assert.assertEquals(Expected, clean);

		dirty = "<!--[if !supportMisalignedColumns]> <style> div { border:1px solid #f00; } </style><![endif]-->";
		clean = xssFilter.doFilter(dirty);

		Assert.assertEquals(Expected, clean);
	}
	
	@Test
	public void testIEHackTagInComment() {
		XssFilter xssFilter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		String clean = xssFilter.doFilter(dirty);
		
		String Expected = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		Assert.assertEquals(Expected, clean);
	}

	@Test
	//Element Class의 remveAllContents Method를 테스트한다.
	//StyleListener에서 해당 메소드를 호출하여 style 태그의 하위에 속하는 모든 child를 제거한다.
	public void testRemoveAllContents() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	@Test
	//IEHack의 비표준을 표준화하여 비표준과 표준의 모두 IEHackExtensionElement로 동일하게 다룬다.
	//Element Class를 extends하였으므로 Element의 모든 기능을 사용할 수 있다. (setName method는 예외로 한다.)
	//이 테스트에서는 비표준을 표준으로 변경하는 기능을 테스트한다.
	//그리고 하위에 속하는 Element들이 적절하게 해당되는 Listener를 타는지 테스트한다.
	//여기서는, 하위의 style element가 StyleListener를 가지도록 설정돼 있다. (@lucy-xss-mail.xml)
	public void testIEHackExtensionElement() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !mso]--><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if !mso]><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testIEHackTagInTheOtherTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<div><!--[if !mso]><p>test</p><![endif]--></div>";
		String clean = filter.doFilter(dirty);
		String expected = "<div><!--[if !mso]><p>test</p><![endif]--></div>";
		Assert.assertEquals(expected, clean);
	}

	@Test
	//IEHackExtensionElement의 모든 객체는 동일한 Element로 간주된다.
	//그래서, 설정파일에서도 대표 이름 하나로 설정한다.
	//<element name="IEHackExtension">
	//IEHackExtension element가 IEHackExtensionListener 를 가지도록 설정했다. (@lucy-xss-mail2.xml)
	public void testIEHackExtensionElementConfig() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");
		String dirty = "<!--[if !mso]--><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	@Test(expected = UnsupportedOperationException.class)
	//IEHackExtensionElement와 Element의 유일한 차이는 IEHack이 setName 메소드를 허용하지 않는 것이다.
	//여기서는 IEHack에서 setName을 호출했을 때 UnsupportedOperationException 이 발생하는 지 테스트한다.
	public void testIEHExElementSetNameOperationDisabled() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail3.xml");
		String dirty = "<!--[if !mso]--><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	@Test
	//상기 testIEHackExtensionElement 테스트에 더해, IEHack 태그에 공백이 들어가는 경우도 기존 IEHack과 동일하게 처리 되는지를 테스트한다.
	public void testIEHackExtensionElementWithSpace() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--        [if !mso]  ><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		System.out.println(expected);
		System.out.println(clean);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testIEHackTagWithoutCloseTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");

		// IE Hack 에서는 Close 태그가 없으면 주석으로 인식되서 뒤에 있는 엘리먼트들 노출에 문제가 생길 수 있다. Close 태그가 없거나 broken 일 때 IE Hack Start 태그를 제거하는 식으로 변경하자.
		String dirty = "<!--[if !IE]><h1>abcd</h1>";
		String clean = filter.doFilter(dirty);
		String expected = "<!-- Removed Tag Filtered (&lt;!--[if !IE]&gt;) --><h1>abcd</h1>";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if]><h1>abcd</h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if !IE]><h1>abcd</h1><![endif]--";
		clean = filter.doFilter(dirty);
		expected = "<!-- Removed Tag Filtered (&lt;!--[if !IE]&gt;) --><h1>abcd</h1>&lt;![endif]--";
		Assert.assertEquals(expected, clean);

	}

	@Test
	public void testIEHackTagWrongGrammar() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !IE><style>abcd</style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !IE><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if]><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[ifaa><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[ifaa><style></style><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	// White Url을 포함하지 않은 src Attribute 에 대한 보안 필터링 하는지 검사한다.
	@Test
	public void testAttributeSrcListener() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-attribure-listener.xml");

		String dirty = "<IMG src=\"http://medlabum.com/cafe/0225/harisu.jpg\" width=\"425\" height=\"344\">";
		String expected = "<IMG src=\"\" width=\"425\" height=\"344\">";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));

		dirty = "<iframe src=\"http://test.com/hello.nhn\" width=\"425\" height=\"344\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;iframe src=\"\" width=\"425\" height=\"344\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}

	@Test
	public void testElementRemoveSimple() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<html><head></head><body><p>Hello</p></body>";
		String expected = "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveBlogRequest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");
		String dirty = "<html><head><style>P {margin-top:2px;margin-bottom:2px;}</style></head><body><div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div></body></html>";
		String expected = "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	
	public void testElementRemoveOPTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span></p>";
		String expected = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font></span></p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveOPTagSimple() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<o:p><font size=\"2\" face=\"바탕\"></font></o:p>";
		String expected = "<!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveOPTagSimple2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<span><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span>";
		String expected = "<span><!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font></span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testKoreanTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");

		String dirty = "<하하하>";
		String expected = "&lt;하하하&gt;"; // 한글은 태그가 아닌 텍스트로 인식해서 블로킹 prefix를 붙이지 않고, escape 처리.
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 블로그개발팀에서 div, table, embed 태그를 다른 모든 태그에서 사용할 수 있도록 하는 방법 테스트
	 * 디폴트 설정에서는 div 태그가 허용되어서는 안된다.
	 */
	@Test
	public void testAgreeDivOnAnyWhereFail() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<span><div><h1>div테스트</h1></div></span>";
		String expected = "<span><!-- Not Allowed Tag Filtered -->&lt;div&gt;<h1>div테스트</h1>&lt;/div&gt;</span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 블로그개발팀에서 div, table, embed 태그를 다른 모든 태그에서 사용할 수 있도록 하는 방법 테스트
	 * 꼼수1 : div, table, embed 태그를 inline 그룹으로 묶는다.
	 */
	@Test
	public void testAgreeDivOnAnyWhere() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-allow-div.xml");

		String dirty = "<span><div><h1>div테스트</h1></div></span>";
		String expected = "<span><div><h1>div테스트</h1></div></span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 엘리먼트 네이밍 테스트
	 */
	@Test
	public void testElementNaming() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");

		String dirty = "<asdf>";
		String expected = "<blocking_asdf>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<aAdFa>";
		expected = "<blocking_aAdFa>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<_a>";
		expected = "<blocking__a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<_a></_a>";
		expected = "<blocking__a></blocking__a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<:a>";
		expected = "<blocking_:a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<a b>";
		expected = "<!-- Not Allowed Attribute Filtered ( b) --><blocking_a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<!a>"; // 요놈은 태그(엘리먼트)로 인식하면 안된다.
		expected = "&lt;!a&gt;"; // 태그가 아닌 텍스트로 인식해서 블로킹 prefix를 붙이지 않고, escape 처리.
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * blockingPrefix 테스트
	 */
	@Test
	public void mailDisableVerifyRequest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mailteam-body-test.xml");

		String dirty = "<base href=\"x-msg://171/\" />";
		String expected = "<xbase href=\"x-msg://171/\" />";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<base href=\"x-msg://171/\" abc=\"abcd\" />";
		expected = "<!-- Not Allowed Attribute Filtered ( abc=\"abcd\") --><xbase href=\"x-msg://171/\" />";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

	}

	@Test
	public void testOnMouseFilter() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-on.xml");

		String dirty1 = " onmouseover=prompt(954996)";
		String dirty2 = URLDecoder.decode("%22%20onmouseover%3dprompt%28954996%29%20bad%3d%22");
		String dirty3 = "\" onmouseover=prompt(954996)\'aa";

		String clean1 = filter.doFilter("paramT", "paramA", dirty1);
		String clean2 = filter.doFilter("paramT", "paramA", dirty2);
		String clean3 = filter.doFilter("paramT", "paramA", dirty3);

		Assert.assertEquals("", clean1);
		Assert.assertEquals("", clean2);
		Assert.assertEquals("\"\"", clean3);

		String orgKeyword = dirty2;//dirty3; //keyword 파라미터에 사용자가 입력하는 경우를 예로 든다.

		XssFilter filter1 = XssFilter.getInstance("lucy-xss-on.xml"); // 새로운 사용자 정의 whitelist file을 만든다 (아래 첨부 내용 참고)
		//이 API 는 version 1.1.0부터 제공합니다. 그 이하 version에서는 기존 방법대로 사용하세요.  단, lucy-xss.xml에 Element와 Attribute정의를 추가해야합니다.

		String[] attList = orgKeyword.split("[\"'`]");

		boolean resultflag = true;

		for (String att : attList) {

			att = "\"" + att + "\"";

			String cleanAtt = filter1.doFilter("paramT", "paramA", att); // 공백으로 구분된 입력 값을 각각 필터링한다.

			if (!att.equals(cleanAtt)) {
				resultflag = false;
			}
		}

		String result = "";

		if (resultflag) {
			result = "Clean User!!";
		} else {
			result = "Dirty User !!";
		}

		Assert.assertEquals("Dirty User !!", result);
	}
	
	/**
	 * 외부에서 Writer를 제어할 수 있는 메소드 추가 테스트 - 메일웹개발팀 김형기 수석님 기능 요구사항
	 * case1 StringWriter
	 * @throws Exception 
	 */
	@Test
	public void externalWriterHandlingMethodAddTestStringWriter() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String valid = readString("xss-normal1.html");
		//String clean = filter.doFilter(valid);
		Writer writer;
		writer = new StringWriter();
		filter.doFilter(valid, writer);
		
		String clean = writer.toString();
		System.out.println("clean : " + clean);
		Assert.assertEquals(valid , clean);
	}
	
	/**
	 * 외부에서 Writer를 제어할 수 있는 메소드 추가 테스트 - 메일웹개발팀 김형기 수석님 기능 요구사항
	 * case2 FileWriter
	 * @throws Exception 
	 */
	@Test
	@Ignore
	public void externalWriterHandlingMethodAddTestFileWriter() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String valid = readString("xss-normal1.html");
		System.out.println("valid : " + valid);
		//String clean = filter.doFilter(valid);
		Writer writer;
		writer = new BufferedWriter(new FileWriter("c:/xss-normal1_dofilter.html"));
		filter.doFilter(valid, writer);
		System.out.println("writer.toString() : " + writer.toString()); 
		writer.flush();
		writer.close();
		
		BufferedReader reader = new BufferedReader(new FileReader("c:/xss-normal1_dofilter.html"));
		String line = "";
		while( (line = reader.readLine()) != null) {
			System.out.println("line : " + line);
		}
	}
	
	/**
	 * 외부에서 Writer를 제어할 수 있는 메소드 추가 테스트 - 메일웹개발팀 김형기 수석님 기능 요구사항
	 * case3 StringWriter
	 * @throws Exception 
	 */
	@Test
	public void externalWriterHandlingMethodAddTestStringWriterEmptyString() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String valid = "";
		//String clean = filter.doFilter(valid);
		Writer writer;
		writer = new StringWriter();
		filter.doFilter(valid, writer);
		
		String clean = writer.toString();
		System.out.println("clean : " + clean);
		Assert.assertEquals(valid , clean);
	}
	
	/**
	 * urlEncoding 된 데이타일경우 처리?
	 */
	@Test
	public void urlEncodingData() {
		XssFilter filter = XssFilter.getInstance();

		// 인코딩 안 된 쿼리
		String valid = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com</script><img src=pooo.png onerror=alert(/V/)>";
		String clean = filter.doFilter(valid);
		System.out.println("clean : " + clean);
		Assert.assertEquals("http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com&lt;/script&gt;<!-- Not Allowed Attribute Filtered ( onerror=alert(/V/)) --><img src=pooo.png>" , clean);
		
		// 인코딩 된 쿼리
		valid = "http://m.id.hangame.com/searchInfo.nhn?type=FINDID&nxtURL=http://m.tera.hangame.com%3C/script%3E%3Cimg%20src=pooo.png%20onerror=alert(/V/)%3E";
		clean = filter.doFilter(valid);
		System.out.println("clean : " + clean);
		Assert.assertEquals(valid , clean);
	}
	
	@Test
	public void elementVsAttributeDisable1() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<body text='test'><p>Hello</p></body>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;body text='test'&gt;<p>Hello</p>&lt;/body&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void elementVsAttributeDisable2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<p src='test'>Hello</p>";
		String expected = "<!-- Not Allowed Attribute Filtered ( src='test') --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void elementVsAttributeDisable3() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<body src='test'>Hello</body>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;body src='test'&gt;Hello&lt;/body&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void neloLogNoXss() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced.xml");
		String targetStr = readString(NORMAL_HTML_FILE);
		String neloStr = filter.doFilterNelo(targetStr);
		Assert.assertEquals("", neloStr);
	}
	
	@Test
	public void neloLogWithXssInvalidFile() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced.xml");
		String targetStr = readString(INVALID_HTML_FILE);
		String neloStr = filter.doFilterNelo(targetStr);
		String expectedNeloStr = "@[XSSFILTER_TEST] (Disabled Element)body\n (Disabled Element)form\n (Disabled Attribute)h2 align=\"center\"\n (Disabled Element)input\n (Disabled Element)input\n";
		Assert.assertEquals(expectedNeloStr, neloStr);
	}
	
	@Test
	public void neloLogWithXssElement1() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced.xml");
		String dirty = "<html><body><br></br><p>hi</p><h1>test</h1></body></html>";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("@[XSSFILTER_TEST] (Disabled Element)body\n (Disabled Element)br\n", neloStr);
	}
	
	@Test
	public void neloLogWithXssElement2() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced.xml");
		String dirty = "<html><body><br><p><p><p><p><p><p><p></body></html>";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("@[XSSFILTER_TEST] (Disabled Element)body\n (Disabled Element)br\n", neloStr);
	}
	
	@Test
	public void neloLogWithXssAttribute() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced.xml");
		String dirty = "<p src='test' href='test' what='test'>Hello</p>";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("@[XSSFILTER_TEST] (Disabled Attribute)p src='test' href='test' what='test'\n", neloStr);
	}
	
	@Test
	public void neloLogRemoveOption() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced-remove.xml");
		String dirty = "<html><head></head><body><h1>Hello</h1></body></html>";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("@[XSSFILTER_TEST] (Removed Element)html\n (Removed Element)head\n (Removed Element)body\n", neloStr);
	}
	
	@Test
	public void neloLogIEHackRemove() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo-advanced-remove.xml");
		String dirty = "<!--[if !supportMisalignedColumns]><h1></h1><![endif]-->";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("@[XSSFILTER_TEST] (Removed Element)<!--[if !supportMisalignedColumns]>\n", neloStr);
	}
	
	@Test
	public void neloLogIEHackAvailabe() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !supportMisalignedColumns]><h1></h1><![endif]-->";
		String neloStr = filter.doFilterNelo(dirty);
		Assert.assertEquals("", neloStr);
	}
	
	/**
	 * src에 script 패턴이 존재 시 무조건 필터링 되는 문제 테스트
	 */
	@Test
	public void notAllowedPatternSrcAttribute() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<img src='http://sstorym.cafe24.com/deScription/lereve/lelogo.gif' width='700'>";
		String expected = "<img src='http://sstorym.cafe24.com/deScription/lereve/lelogo.gif' width='700'>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='scription/lereve/lelogo.gif' width='700'>";
		expected = "<img src='scription/lereve/lelogo.gif' width='700'>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='script:/lereve/lelogo.gif' width='700'>";
		expected = "<!-- Not Allowed Attribute Filtered ( src='script:/lereve/lelogo.gif') --><img width='700'>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * 모든 태그에서 class 속성을 허용하지 않고, table 태그에서만 class 속성을 허용 - 메일웹개발팀 이우철
	 */
	@Test
	public void disableClassAttrExceptTable() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail-table-class-available.xml");
		// exceptionTagList 에 포함 된 element 는 attribute 의 disable 속성에 영향을 안 받도록 예외처리가 잘 되는지 확인.
		String dirty = "<table class='test'></table>";
		String expected = "<table class='test'></table>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// exceptionTagList 에 없는 태그들은 attribute 의 disable 속성이 true 되어 있으면 필터링 되는지 확인.
		dirty = "<div class='test'></div>";
		expected = "<!-- Not Allowed Attribute Filtered ( class='test') --><div></div>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// exceptionTagList로 예외처리가 되었어도, element 의 속성요소로 설정이 안되어 있는 경우 disable 되는지 확인
		dirty = "<span class='test'></span>";
		expected = "<!-- Not Allowed Attribute Filtered ( class='test') --><span></span>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// exceptionTagList로 예외처리가 되었어도, value 가 문제 있을 경우 disable 되는지 확인
		dirty = "<table class='script'></table>";
		expected = "<!-- Not Allowed Attribute Filtered ( class='script') --><table></table>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
	}
	
	/**
	 * Href 속성에서 javascript 패턴 존재하는지 테스트
	 */
	@Test
	public void hrefAttackTest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<a HREF=\"javascript:alert('XSS');\"></a>";
		String expected = "<!-- Not Allowed Attribute Filtered ( HREF=\"javascript:alert('XSS');\") --><a></a>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * Link 태그가 escape 되는지 테스트
	 */
	@Test
	public void linkAttackTest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void styleAttackTest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;DIV STYLE=\"background-image: url(javascript:alert('XSS'))\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	

	@Test
	public void illegalAttributeEnd() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<colgroup width=\"";
		String expected = "<colgroup width=\"\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void endTagWithoutStartTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "</p>";
		String expected = "&lt;/p&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void html5TagVideo() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<video></video>";
		String expected = "<video></video>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\"></video>";
		expected = dirty;
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" pubdate=\"\"></video>";
		expected = "<video width=\"320\" height=\"240\" controls=\"controls\"><!-- Not Allowed Attribute Filtered ( pubdate=\"\") --><source src=\"movie.mp4\" type=\"video/mp4\"></video>"; // pubdate=\"\" 필터링 됨
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void html5TagVideoInDiv() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<div><video></video></div>";
		String expected = "<div><video></video></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void withoutCommentMultiThreadTest() {
		String expectedWithComment = "<!-- Not Allowed Tag Filtered -->&lt;body text='test'&gt;&lt;/body&gt;";
		String expectedWithoutComment = "&lt;body text='test'&gt;&lt;/body&gt;";
		
		ExecutorService service = Executors.newFixedThreadPool(10);
		int count = 2;
		final CountDownLatch latch = new CountDownLatch(count);
		final ConcurrentHashMap<Integer, String> result = new ConcurrentHashMap<Integer, String>();
		
		try {
			for(int i=0; i< count; i++) {
				final int index = i;
				service.execute(new Runnable() {
					
					public void run() {
						try {
							XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml", index % 2 == 0?false:true); // 짝수면 주석추가, 홀수면 주석생략
							String dirty = "<body text='test'></body>";
							
							String clean = filter.doFilter(dirty);
							System.out.println("clean : " + clean);
							result.put(index, clean);
						} finally {
							latch.countDown();
						}
					}
				});
			}
			
			latch.await();
			
		} catch (Exception e) {
			 throw new RuntimeException(e);
		} finally {
			service.shutdown();
		}
		
		Enumeration<Integer> keys = result.keys();
		while(keys.hasMoreElements()) {
			Integer nextKey = keys.nextElement();
			if (nextKey%2 == 0) { // 짝수면 주석이 있어야함
				Assert.assertEquals(expectedWithComment, result.get(nextKey));
			} else { // 홀수면 주석 생략되어야함.
				Assert.assertEquals(expectedWithoutComment, result.get(nextKey));
			}
		}
	}
	
	@Test
	public void variousInputMultiThreadTest() {
		ExecutorService service = Executors.newFixedThreadPool(100);
		int runCount = 10000;
		final CountDownLatch latch = new CountDownLatch(runCount);
		final ConcurrentHashMap<Integer, String> result = new ConcurrentHashMap<Integer, String>();
		
		try {
			for(int i=0; i< runCount; i++) {
				final int index = i;
				service.execute(new Runnable() {
					
					public void run() {
						try {
							XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
							String dirty = targetString[index % targetString.length];
							String clean = filter.doFilter(dirty);
							result.put(index, clean);
						} finally {
							latch.countDown();
						}
					}
				});
			}
			
			latch.await();
			
		} catch (Exception e) {
			 throw new RuntimeException(e);
		} finally {
			service.shutdown();
		}
		
		Enumeration<Integer> keys = result.keys();
		while(keys.hasMoreElements()) {
			Integer nextKey = keys.nextElement();
			Assert.assertEquals(expectedString[nextKey % targetString.length], result.get(nextKey));
		}
	}
	
	@Test
	public void variousInputVariousConfigMultiThreadTest() {
		ExecutorService service = Executors.newFixedThreadPool(100);
		int runCount = 10000;
		final CountDownLatch latch = new CountDownLatch(runCount);
		final ConcurrentHashMap<Integer, String> result = new ConcurrentHashMap<Integer, String>();
		
		try {
			for(int i=0; i< runCount; i++) {
				final int index = i;
				service.execute(new Runnable() {
					
					public void run() {
						try {
							XssFilter filter = XssFilter.getInstance(configFile[index % configFile.length]);
							String dirty = targetStringOnOtherConfig[index % targetStringOnOtherConfig.length];
							String clean = filter.doFilter(dirty);
							result.put(index, clean);
						} finally {
							latch.countDown();
						}
					}
				});
			}
			
			latch.await();
			
		} catch (Exception e) {
			 throw new RuntimeException(e);
		} finally {
			service.shutdown();
		}
		
		Enumeration<Integer> keys = result.keys();
		while(keys.hasMoreElements()) {
			Integer nextKey = keys.nextElement();
			Assert.assertEquals(expectedStringOnOtherConfig[nextKey % targetStringOnOtherConfig.length], result.get(nextKey));
		}
	}
	
	@Test
	public void shopCharTest() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "#Test";
		String clean = filter.doFilter(dirty);
		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		Assert.assertTrue("\n" + dirty + "\n" + clean, dirty.equals(clean));
	}
	
	@Test
	public void shopCharTest2() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String clean = filter.doFilter("span", "id", "test as");
		System.out.println(clean);
	}
	
	/**
	 * 속성에 주석 닫는 태그(--&gt;) 있을 경우에 이스케이프가 잘 되는지 확인.
	 * 속성에 주석 닫는 태그가 있으면 주석으로 처리하는 로직이 깨질 수 있어서 방어해야함.
	 * @throws Exception
	 */
	@Test
	public void atributeComment() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<p tt='-->'>Hello</p>";
		String expected = "<!-- Not Allowed Attribute Filtered ( tt='--&gt;') --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void noAtribute() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<p>Hello</p>";
		String expected = "<p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * EmbedListener.java 테스트
	 * embed 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크, type 추가를 통한 방어
	 */
	@Test
	public void embedListenerWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed.xml");
		// white url이면 html 도 통과시킨다.
		String dirty = "<embed type=\"text/html\" src=\"http://serviceapi.nmv.naver.com/\" >";
		String expected = "<embed type=\"text/html\" src=\"http://serviceapi.nmv.naver.com/\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"all\">" ;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
			
		// type 속성 체크 테스트(위험)
		dirty = "<embed type=\"text/html\" src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed type=\"text/html\" src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(일반)
		dirty = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\"";
		expected = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<embed type=\"\" src=\"http://www.w3schools.com/html5/helloworld.swf\">";
		expected = "<embed type=\"application/x-shockwave-flash\" src=\"http://www.w3schools.com/html5/helloworld.swf\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<embed type=\"\" src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed type=\"\" src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
				
		// url 확장자 체크 테스트(위험)
		dirty = "<embed src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\">";
		expected = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시?) - 통과시키자.
		dirty = "<embed src=\"http://www.w3schools.com/\">";
		expected = "<embed src=\"http://www.w3schools.com/\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면??? ) - 통과시키지 말자.
		dirty = "<embed src=\"http://test.mireene.com/test.test\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://test.mireene.com/test.test\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * EmbedSecurityListener.java 테스트 - EmbedListener + http content-type 체크
	 * embed 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크 + @(http content-type 체크) type 추가를 통한 방어
	 */
	@Test
	public void embedSecurityListenerWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
		// white url이면 html 도 통과시킨다.
		String dirty = "<embed type=\"text/html\" src=\"http://serviceapi.nmv.naver.com/\" >";
		String expected = "<embed type=\"text/html\" src=\"http://serviceapi.nmv.naver.com/\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"all\">" ;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
			
		// type 속성 체크 테스트(위험)
		dirty = "<embed type=\"text/html\" src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed type=\"text/html\" src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(일반)
		dirty = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\"";
		expected = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<embed type=\"\" src=\"http://www.w3schools.com/html5/helloworld.swf\">";
		expected = "<embed type=\"application/x-shockwave-flash\" src=\"http://www.w3schools.com/html5/helloworld.swf\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<embed type=\"\" src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed type=\"\" src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
				
		// url 확장자 체크 테스트(위험)
		dirty = "<embed src=\"http://test.mireene.com/xss.html\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://test.mireene.com/xss.html\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\">";
		expected = "<embed src=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
		dirty = "<embed src=\"http://www.w3schools.com/\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://www.w3schools.com/\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<embed src=\"http://www.w3schools.com/\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://www.w3schools.com/\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면) - 통과시키지 말자.
		dirty = "<embed src=\"http://test.mireene.com/test.test\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://test.mireene.com/test.test\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 에 확장자가 없고 존재하지(404 Not found) 않으면? - 통과시키지 말자.
		dirty = "<embed src=\"http://test.mireene.com/\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://test.mireene.com/\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * ObjectListener.java 테스트
	 * object 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크, type 추가를 통한 방어
	 * url이 object 태그가 아닌 자식 태그인 param 태그의 src, href, movie 이름을 갖는 데이타로 올 경우 
	 */
	@Test
	public void objectListenerParamTagUrlWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed.xml");
		
		// white url이면 html 도 통과시킨다.
		String dirty = "<object type=\"text/html\"><param name=\"src\" value=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<object type=\"text/html\"><param name=\"src\" value=\"http://serviceapi.nmv.naver.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"all\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(위험)
		dirty = "<object type=\"text/html\"><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"text/html\"&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(일반)
		dirty = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<object type=\"\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<object type=\"\"><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"\"&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
		// url 확장자 체크 테스트(위험)
		dirty = "<object><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<object><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시?) - 통과시키자.
		dirty = "<object><param name=\"src\" value=\"http://www.w3schools.com/\"></object>";
		expected = "<object><param name=\"src\" value=\"http://www.w3schools.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면??? ) - 통과시키지 말자.
		dirty = "<object><param name=\"src\" value=\"http://test.mireene.com/xss.test\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.test\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		
	}
	
	/**
	 * ObjectListener.java 테스트 - EmbedListener + http content-type 체크
	 * object 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크, type 추가를 통한 방어
	 * url이 param 태그가 아닌, object의 data 속성으로 올 경우에도, 위 테스트 메소드(objectListenerParamTagUrlWhitelistAndTypeCheck)에서 수행한 테스트들이 성공해야한다.
	 */
	@Test
	public void objectListenerDataAttributeWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed.xml");
		
		// white url이면 html 도 통과시킨다.
		String dirty = "<object type=\"text/html\" data=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<object type=\"text/html\" data=\"http://serviceapi.nmv.naver.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"all\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(위험)
		dirty = "<object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		
		// type 속성 체크 테스트(일반)
		dirty = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<object type=\"\" data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<object type=\"\" data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"\" data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
		// url 확장자 체크 테스트(위험)
		dirty = "<object data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<object data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object data=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시?) - 통과시키자.
		dirty = "<object data=\"http://www.w3schools.com/\"></object>";
		expected = "<object data=\"http://www.w3schools.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면??? ) - 통과시키지 말자.
		dirty = "<object data=\"http://test.mireene.com/xss.test\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://test.mireene.com/xss.test\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	

	/**
	 * ObjectSecurityListener.java 테스트 - ObjectListener + http content-type 체크
	 * object 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크, type 추가를 통한 방어
	 * url이 object 태그가 아닌 자식 태그인 param 태그의 src, href, movie 이름을 갖는 데이타로 올 경우 
	 */
	@Test
	public void objectSecurityListenerParamTagUrlWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
		
		// white url이면 html 도 통과시킨다.
		String dirty = "<object type=\"text/html\"><param name=\"src\" value=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<object type=\"text/html\"><param name=\"src\" value=\"http://serviceapi.nmv.naver.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"all\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(위험)
		dirty = "<object type=\"text/html\"><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"text/html\"&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(일반)
		dirty = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<object type=\"\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<object type=\"\"><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"\"&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
		// url 확장자 체크 테스트(위험)
		dirty = "<object><param name=\"src\" value=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.html\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<object><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\"><param name=\"src\" value=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
		dirty = "<object><param name=\"src\" value=\"http://www.w3schools.com/\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://www.w3schools.com/\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면) - 통과시키지 말자.
		dirty = "<object><param name=\"src\" value=\"http://test.mireene.com/xss.test\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://test.mireene.com/xss.test\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 에 확장자가 없고 존재하지(404 Not found) 않으면? - 통과시키지 말자.
		dirty = "<object><param name=\"src\" value=\"http://test.mireene.com/\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object&gt;<param name=\"src\" value=\"http://test.mireene.com/\">&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
	}
	
	/**
	 * ObjectSecurityListener.java 테스트 - ObjectListener + http content-type 체크
	 * object 관련 취약성 대응 - 화이트리스트 체크 및 type 속성 체크, url 파일 확장자 체크, type 추가를 통한 방어
	 * url이 param 태그가 아닌, object의 data 속성으로 올 경우에도, 위 테스트 메소드(objectListenerParamTagUrlWhitelistAndTypeCheck)에서 수행한 테스트들이 성공해야한다.
	 */
	@Test
	public void objectSecurityListenerDataAttributeWhitelistAndTypeCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
		
		// white url이면 html 도 통과시킨다.
		String dirty = "<object type=\"text/html\" data=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<object type=\"text/html\" data=\"http://serviceapi.nmv.naver.com/\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"all\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 체크 테스트(위험)
		dirty = "<object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		
		// type 속성 체크 테스트(일반)
		dirty = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (일반)
		dirty = "<object type=\"\" data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object type=\"application/x-shockwave-flash\" data=\"http://www.w3schools.com/html5/helloworld.swf\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// type 속성 값 공백일 경우에는 확장자 체크해서 type 속성 변경해주나? (위험)
		dirty = "<object type=\"\" data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"\" data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
		// url 확장자 체크 테스트(위험)
		dirty = "<object data=\"http://test.mireene.com/xss.html\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(일반)
		dirty = "<object data=\"http://www.w3schools.com/html5/helloworld.swf\"></object>";
		expected = "<object data=\"http://www.w3schools.com/html5/helloworld.swf\" type=\"application/x-shockwave-flash\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
		dirty = "<object data=\"http://www.w3schools.com/\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://www.w3schools.com/\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		// url 확장자 체크 테스트(url의 확장자로 등록된게 아니면) - 통과시키지 말자.
		dirty = "<object data=\"http://test.mireene.com/xss.test\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://test.mireene.com/xss.test\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
				
		// url 에 확장자가 없고 존재하지(404 Not found) 않으면? - 통과시키지 말자.
		dirty = "<object data=\"http://test.mireene.com/\"></object>";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://test.mireene.com/\"&gt;&lt;/object&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Ignore
	@Test
	public void objectSecurityListenerManyTimes() {
		for(int i=0; i<1000000;i++) {
			XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
			
			// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
			String dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=409628&no=" + i + "\"></object>";
			filter.doFilter(dirty);
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
			}
		}
	}
	
	@Test
	public void objectSecurityListenerCache() {
		for(int i=0; i<10;i++) {
			XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
			
			// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
			String dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=409628&no=23\"></object>";
			filter.doFilter(dirty);
		}
	}
	
	@Test
	public void objectSecurityListenerCacheDiffConfig() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
		String dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=409628&no=23\"></object>";
		filter.doFilter(dirty);
		
		filter = XssFilter.getInstance("lucy-xss-embed-security2.xml");
		// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
		dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=409628&no=23\"></object>";
		filter.doFilter(dirty);
	}
	
	@Test
	public void objectSecurityListenerCacheEachThread() {
		
		ExecutorService service = Executors.newFixedThreadPool(5);
		final CountDownLatch latch = new CountDownLatch(10);
		for(int i=0; i< 10; i++) {
			service.execute(new Runnable() {
				public void run() {
					try {
					XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
					
					// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
					String dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=409628&no=23\"></object>";
					filter.doFilter(dirty);
					} finally {
						latch.countDown();
					}
				}
			});
		}
		
		try {
			latch.await();
		} catch (InterruptedException e) {
		}
	}
	
	@Ignore
	@Test
	public void objectSecurityListenerCacheEachThreadManyTimes() {
		
		ExecutorService service = Executors.newFixedThreadPool(5);
		int count = 100000;
		final CountDownLatch latch = new CountDownLatch(count);
		for(int i=0; i< count; i++) {
			final int loopCnt = i;
			service.execute(new Runnable() {
				public void run() {
					try {
					XssFilter filter = XssFilter.getInstance("lucy-xss-embed-security.xml");
					
					// url 확장자 체크 테스트(url에 확장자가 없어서 타입 확인 불가시, 타입은 Response Header 가지고 체크) - text/* 이면 통과시키지 말자.
					String dirty = "<object data=\"http://comic.naver.com/webtoon/detail.nhn?titleId=" + loopCnt +"&no=23\"></object>";
					filter.doFilter(dirty);
					} finally {
						latch.countDown();
					}
				}
			});
		}
		
		try {
			latch.await();
		} catch (InterruptedException e) {
		}
	}
	
	@Test
	public void objectListenerOnSuperset() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<object data=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://serviceapi.nmv.naver.com/\"&gt;&lt;/object&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void embedListenerOnSuperset() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<embed src=\"http://serviceapi.nmv.naver.com/\">";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;embed src=\"http://serviceapi.nmv.naver.com/\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * Iehack 태그는 어느 태그 밑에도 올 수 있어야 한다.
	 */
	@Test
	public void iehackInBodyCase() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-body.xml");
		
		String dirty = "<html><head></head><body><!--[if gte vml 1]><v:shapetype id=\"_x0000_t201\"><![if excel]><x:ClientData ObjectType=\"Drop\"> <x:DropLines>123123 8</x:DropLines> </x:ClientData> <![endif]> </v:shape><![endif]--></body></html>";
		String expected = "<html><head></head><body><!--[if gte vml 1]><!-- Not Allowed Attribute Filtered ( id=\"_x0000_t201\") --><xv:shapetype><![if excel]><!-- Not Allowed Attribute Filtered ( ObjectType=\"Drop\") --><xx:ClientData> <xx:DropLines>123123 8</xx:DropLines> </xx:ClientData> <![endif]> &lt;/v:shape&gt;<![endif]--></body></html>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void nestedIehack() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<!--[if gte vml 1]><![if excel]><![endif]><![endif]-->";
		String expected = "<!--[if gte vml 1]><![if excel]><![endif]><![endif]-->";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<!--[if gte vml 1]--><![if excel]><![endif]><!--[endif]-->";
		expected = "<!--[if gte vml 1]><![if excel]><![endif]><![endif]-->";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<!--[if gte vml 1]--><!--[endif]-->";
		expected = "<!--[if gte vml 1]><![endif]-->";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<![if excel]>asdf<![endif]>";
		expected = "<![if excel]>asdf<![endif]>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testBase64EmbedSrc() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";
		String expected = "<!-- Not Allowed Attribute Filtered ( SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\") --><EMBED type=\"image/svg+xml\" allowScriptAccess=\"never\" invokeURLs=\"false\" autostart=\"false\" allowNetworking=\"internal\"></EMBED>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testObjectTagDataUrlWithParameter() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<object data=\"http://www.1.com/2.swf?1234\"></object>";
		String expected = "<object data=\"http://www.1.com/2.swf?1234\" type=\"application/x-shockwave-flash\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testObjectTagDataUrlWithParameterNegative() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<object data=\"http://www.1.com/2.html?1234\"></object>";
		String expected = "<blocking_object data=\"http://www.1.com/2.html?1234\"></blocking_object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	
	@Test
	public void pairQuoteCheck() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<img src=\"http:/><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		String expected = "<img src=\"http:/\"><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='http:/><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src='http:/'><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=http:/'><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src='http:/'><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=http:/\"><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=\"http:/\"><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=\"><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=\"\"><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=''><!-- Not Allowed Tag Filtered -->&lt;a target=\" _blank=\"&gt;_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void pairQuoteCheckOtherCase() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<img src=\"<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
		String expected = "<img src=\"\"><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
		expected = "<img src=''><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * 샵N에서 url 체크 기능이 없는 기존 버전을 사용한다고해서 기존 objectListner 를 사용했을 경우의 테스트
	 */
	@Test
	public void shopNObjectListenerOld() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-shopn.xml");
		String dirty = "<OBJECT id=dv1341982729683 codeBase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=9,0,28,0\" classid=clsid:d27cdb6e-ae6d-11cf-96b8-444553540000 width=600 height=700>"
			+ "<PARAM NAME=\"_cx\" VALUE=\"15875\">"
			+ "<PARAM NAME=\"_cy\" VALUE=\"18520\">"
			+ "<PARAM NAME=\"FlashVars\" VALUE=\"\">"
			+ "<PARAM NAME=\"Movie\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\">"
			+ "<PARAM NAME=\"Src\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\">"
			+ "<PARAM NAME=\"WMode\" VALUE=\"Transparent\">"
			+ "<PARAM NAME=\"Play\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Loop\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Quality\" VALUE=\"High\">"
			+ "<PARAM NAME=\"SAlign\" VALUE=\"\">"
			+ "<PARAM NAME=\"Menu\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Base\" VALUE=\"\">"
			+ "<PARAM NAME=\"AllowScriptAccess\" VALUE=\"always\">"
			+ "<PARAM NAME=\"Scale\" VALUE=\"ShowAll\">"
			+ "<PARAM NAME=\"DeviceFont\" VALUE=\"0\">"
			+ "<PARAM NAME=\"EmbedMovie\" VALUE=\"0\">"
			+ "<PARAM NAME=\"BGColor\" VALUE=\"\">"
			+ "<PARAM NAME=\"SWRemote\" VALUE=\"\">"
			+ "<PARAM NAME=\"MovieData\" VALUE=\"\">"
			+ "<PARAM NAME=\"SeamlessTabbing\" VALUE=\"1\">"
			+ "<PARAM NAME=\"Profile\" VALUE=\"0\">"
			+ "<PARAM NAME=\"ProfileAddress\" VALUE=\"\">"
			+ "<PARAM NAME=\"ProfilePort\" VALUE=\"0\">"
			+ "<PARAM NAME=\"AllowNetworking\" VALUE=\"all\">"
			+ "<PARAM NAME=\"AllowFullScreen\" VALUE=\"true\">"
			+ "<PARAM NAME=\"AllowFullScreenInteractive\" VALUE=\"\">" 
			+ "<embed src=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&tic=1341982706\" type=\"application/x-shockwave-flash\" name=\"dv1341982729683\" wmode=\"transparent\" allowscriptaccess=\"always\" width=\"600\" height=\"700\" allowfullscreen=\"true\" quality=\"high\">"
			+ "</embed>"
			+ "</OBJECT>";
		String expected = "<OBJECT id=dv1341982729683 codeBase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=9,0,28,0\" classid=clsid:d27cdb6e-ae6d-11cf-96b8-444553540000 width=600 height=700><PARAM NAME=\"_cx\" VALUE=\"15875\"><PARAM NAME=\"_cy\" VALUE=\"18520\"><PARAM NAME=\"FlashVars\" VALUE=\"\"><PARAM NAME=\"Movie\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\"><PARAM NAME=\"Src\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\"><PARAM NAME=\"WMode\" VALUE=\"Transparent\"><PARAM NAME=\"Play\" VALUE=\"-1\"><PARAM NAME=\"Loop\" VALUE=\"-1\"><PARAM NAME=\"Quality\" VALUE=\"High\"><PARAM NAME=\"SAlign\" VALUE=\"\"><PARAM NAME=\"Menu\" VALUE=\"-1\"><PARAM NAME=\"Base\" VALUE=\"\"><PARAM NAME=\"AllowScriptAccess\" value=\"never\"><PARAM NAME=\"Scale\" VALUE=\"ShowAll\"><PARAM NAME=\"DeviceFont\" VALUE=\"0\"><PARAM NAME=\"EmbedMovie\" VALUE=\"0\"><PARAM NAME=\"BGColor\" VALUE=\"\"><PARAM NAME=\"SWRemote\" VALUE=\"\"><PARAM NAME=\"MovieData\" VALUE=\"\"><PARAM NAME=\"SeamlessTabbing\" VALUE=\"1\"><PARAM NAME=\"Profile\" VALUE=\"0\"><PARAM NAME=\"ProfileAddress\" VALUE=\"\"><PARAM NAME=\"ProfilePort\" VALUE=\"0\"><PARAM NAME=\"AllowNetworking\" value=\"internal\"><PARAM NAME=\"AllowFullScreen\" VALUE=\"true\"><PARAM NAME=\"AllowFullScreenInteractive\" VALUE=\"\"><!-- Not Allowed Attribute Filtered ( wmode=\"transparent\" allowfullscreen=\"true\" quality=\"high\") --><embed src=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&tic=1341982706\" type=\"application/x-shockwave-flash\" name=\"dv1341982729683\" allowScriptAccess=\"never\" width=\"600\" height=\"700\" invokeURLs=\"false\" autostart=\"false\" allowNetworking=\"internal\"></embed><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></OBJECT>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * 샵N에서 object listener 사용 시 추가적으로 허용 할 확장자를 프로퍼티 파일을 통해 설정할 경우 테스트
	 */
	@Test
	public void shopNObjectListenerAdditionalExtensionSetup() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<OBJECT id=dv1341982729683 codeBase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=9,0,28,0\" classid=clsid:d27cdb6e-ae6d-11cf-96b8-444553540000 width=600 height=700>"
			+ "<PARAM NAME=\"_cx\" VALUE=\"15875\">"
			+ "<PARAM NAME=\"_cy\" VALUE=\"18520\">"
			+ "<PARAM NAME=\"FlashVars\" VALUE=\"\">"
			+ "<PARAM NAME=\"Movie\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\">"
			+ "<PARAM NAME=\"Src\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\">"
			+ "<PARAM NAME=\"WMode\" VALUE=\"Transparent\">"
			+ "<PARAM NAME=\"Play\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Loop\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Quality\" VALUE=\"High\">"
			+ "<PARAM NAME=\"SAlign\" VALUE=\"\">"
			+ "<PARAM NAME=\"Menu\" VALUE=\"-1\">"
			+ "<PARAM NAME=\"Base\" VALUE=\"\">"
			+ "<PARAM NAME=\"AllowScriptAccess\" VALUE=\"always\">"
			+ "<PARAM NAME=\"Scale\" VALUE=\"ShowAll\">"
			+ "<PARAM NAME=\"DeviceFont\" VALUE=\"0\">"
			+ "<PARAM NAME=\"EmbedMovie\" VALUE=\"0\">"
			+ "<PARAM NAME=\"BGColor\" VALUE=\"\">"
			+ "<PARAM NAME=\"SWRemote\" VALUE=\"\">"
			+ "<PARAM NAME=\"MovieData\" VALUE=\"\">"
			+ "<PARAM NAME=\"SeamlessTabbing\" VALUE=\"1\">"
			+ "<PARAM NAME=\"Profile\" VALUE=\"0\">"
			+ "<PARAM NAME=\"ProfileAddress\" VALUE=\"\">"
			+ "<PARAM NAME=\"ProfilePort\" VALUE=\"0\">"
			+ "<PARAM NAME=\"AllowNetworking\" VALUE=\"all\">"
			+ "<PARAM NAME=\"AllowFullScreen\" VALUE=\"true\">"
			+ "<PARAM NAME=\"AllowFullScreenInteractive\" VALUE=\"\">" 
			+ "<embed src=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&tic=1341982706\" type=\"application/x-shockwave-flash\" name=\"dv1341982729683\" wmode=\"transparent\" allowscriptaccess=\"always\" width=\"600\" height=\"700\" allowfullscreen=\"true\" quality=\"high\">"
			+ "</embed>"
			+ "</OBJECT>";
		String expected = "<OBJECT id=dv1341982729683 codeBase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=9,0,28,0\" classid=clsid:d27cdb6e-ae6d-11cf-96b8-444553540000 width=600 height=700 type=\"dvs\"><PARAM NAME=\"_cx\" VALUE=\"15875\"><PARAM NAME=\"_cy\" VALUE=\"18520\"><PARAM NAME=\"FlashVars\" VALUE=\"\"><PARAM NAME=\"Movie\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\"><PARAM NAME=\"Src\" VALUE=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&amp;tic=1341982706\"><PARAM NAME=\"WMode\" VALUE=\"Transparent\"><PARAM NAME=\"Play\" VALUE=\"-1\"><PARAM NAME=\"Loop\" VALUE=\"-1\"><PARAM NAME=\"Quality\" VALUE=\"High\"><PARAM NAME=\"SAlign\" VALUE=\"\"><PARAM NAME=\"Menu\" VALUE=\"-1\"><PARAM NAME=\"Base\" VALUE=\"\"><PARAM NAME=\"AllowScriptAccess\" value=\"never\"><PARAM NAME=\"Scale\" VALUE=\"ShowAll\"><PARAM NAME=\"DeviceFont\" VALUE=\"0\"><PARAM NAME=\"EmbedMovie\" VALUE=\"0\"><PARAM NAME=\"BGColor\" VALUE=\"\"><PARAM NAME=\"SWRemote\" VALUE=\"\"><PARAM NAME=\"MovieData\" VALUE=\"\"><PARAM NAME=\"SeamlessTabbing\" VALUE=\"1\"><PARAM NAME=\"Profile\" VALUE=\"0\"><PARAM NAME=\"ProfileAddress\" VALUE=\"\"><PARAM NAME=\"ProfilePort\" VALUE=\"0\"><PARAM NAME=\"AllowNetworking\" value=\"internal\"><PARAM NAME=\"AllowFullScreen\" VALUE=\"true\"><PARAM NAME=\"AllowFullScreenInteractive\" VALUE=\"\"><!-- Not Allowed Attribute Filtered ( wmode=\"transparent\" allowfullscreen=\"true\" quality=\"high\") --><embed src=\"http://storage.detailview.co.kr/skin/detailview3.dvs?id=183774&tic=1341982706\" type=\"application/x-shockwave-flash\" name=\"dv1341982729683\" allowScriptAccess=\"never\" width=\"600\" height=\"700\" invokeURLs=\"false\" autostart=\"false\" allowNetworking=\"internal\"></embed><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></OBJECT>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void ieHackHasXssCase() {
		XssFilter filter = XssFilter.getInstance();
		String dirty = "<!--[if <img src=x onerror=alert(123) //] -->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if &lt;img src=x onerror=alert(123) //]>";
	
		Assert.assertEquals(expected, clean);
	}
}