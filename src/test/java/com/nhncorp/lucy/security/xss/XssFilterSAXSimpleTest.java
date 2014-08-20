/*
 * @(#) XssFilterSAXSimpleTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
public class XssFilterSAXSimpleTest extends XssFilterTestCase {
	private static final String DIRTY_CODES_FILE = "xss-dirtycodes.txt";
	private static final String NORMAL_HTML_FILE = "xss-normal1.html";
	private static final String INVALID_HTML_FILE1 = "xss-invalid1.html";
	private static final String INVALID_HTML_FILE2 = "xss-invalid2.html";
	private static final String INVALID_HTML_FILE3 = "xss-invalid3.html";
	
	private static final String[] targetString = {"<script></script>", "<body text='test'><p>Hello</p></body>", "<img src='script:/lereve/lelogo.gif' width='700'>"};
	private static final String[] expectedString = {"<!-- Not Allowed Tag Filtered -->&lt;script&gt;&lt;/script&gt;", "<!-- Not Allowed Tag Filtered -->&lt;body text='test'&gt;<p>Hello</p>&lt;/body&gt;", "<!-- Not Allowed Attribute Filtered ( src='script:/lereve/lelogo.gif') --><img width='700'>"};
	
	private static final String[] configFile = {"lucy-xss-superset-sax.xml", "lucy-xss-sax-simple.xml", "lucy-xss-superset-sax.xml", "lucy-xss-sax-blog-removetag.xml"};
	private static final String[] targetStringOnOtherConfig = {"<img src='script:/lereve/lelogo.gif' width='700'>", "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->", "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->", "<html><head></head><body><p>Hello</p></body>"};
	private static final String[] expectedStringOnOtherConfig = {"<!-- Not Allowed Attribute Filtered ( src='script:/lereve/lelogo.gif') --><img width='700'>", "<!--[if !supportMisalignedColumns]><h1>Hello</h1><![endif]-->", "<!--[if !supportMisalignedColumns]><h1>Hello</h1><![endif]-->", "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><p>Hello</p>"};

	/**
	 * 표준 HTML 페이지를 통과 시키는지 검사한다.(필터링 전후가 동일하면 정상)
	 * @throws Exception
	 */
	@Test
	public void testStandardHtmlFiltering() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String valid = readString(NORMAL_HTML_FILE);
		String clean = filter.doFilter(valid);
		Assert.assertTrue("\n" + valid + "\n" + clean, valid.equals(clean));
	}
	
	/**
	 * 비표준 HTML 페이지를 통과 시키는지 검사한다.(필터링 전후가 동일하면 정상)
	 * @throws Exception
	 */
	@Test
	public void testNonStandardHtmlFiltering() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = readString(INVALID_HTML_FILE3);
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(dirty, clean);
	}

	/**
	 * JavaScript와 같은 공격적인 코드를 필터링 하는지 검사한다.(필터링 전후가 틀려야 정상)
	 * @throws Exception
	 */
	@Test
	public void testDirtyCodeFiltering() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = readString(DIRTY_CODES_FILE);
		String clean = filter.doFilter(dirty);
		System.out.println("clean : " + clean);
		Assert.assertFalse("\n" + dirty + "\n" + clean, dirty.equals(clean));
	}

	/**
	 * 허용되지 않은 element, attribute 를 필터링 하는지 검사한다. (필터링 전후가 틀려야 정상)
	 * @throws Exception
	 */
	@Test
	public void testCrackCodeFiltering() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = readString(INVALID_HTML_FILE1);
		String clean = filter.doFilter(dirty);
		String expected = "<html><head><title>제품 정보</title></head><!-- Not Allowed Tag Filtered -->&lt;body&gt;<form name=\"myform\" action=\"\" method=\"post\"><h2 align=\"center\">제품 정보</h2><input type=\"submit\" value=\"등록하기\"> &nbsp; <input type=\"reset\">value=\"취소\"&gt;</p>&lt;/body&gt;</html>";
		Assert.assertEquals(expected, clean);
		
		dirty = readString(INVALID_HTML_FILE2);
		clean = filter.doFilter(dirty);
		expected = "<a href=\"naver.com\" name=\"rich\">참고</a>하세요.";
		Assert.assertEquals(expected, clean);
	}

	/**
	 * White Url을 포함하지 않은 Embed 태그에 대한 보안 필터링 하는지 검사한다.
	 * @throws Exception
	 */
	@Test
	public void testEmbedListener() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml");

		String dirty = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\">";
		String expected = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\" type=\"video/x-ms-wmv\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}

	/**
	 * White Url을 포함한 Embed 태그에 대한 보안 필터링 하는지 검사한다.
	 * @throws Exception
	 */
	@Test
	public void testEmbedListenerWithWhiteUrl() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml");

		String dirty = "<EMBED src=\"http://play.tagstory.com/player/harisu.wmv\" width=\"425\" height=\"344\">";
		String expected = "<EMBED src=\"http://play.tagstory.com/player/harisu.wmv\" width=\"425\" height=\"344\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"all\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 중첩된 Object 태그에 대한 보안 필터링 하는지 검사한다.
	 * @throws Exception
	 */
	@Test
	public void testObjectLoopListener() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");

		String dirty = readString("xss-dirtyobject.html");
		String expected = readString("xss-dirtyobject-expected.html");
		String clean = filter.doFilter(dirty);
		System.out.println("dirty    : " + dirty);
		System.out.println("expected : " + expected);
		System.out.println("clean    : " + clean);
		Assert.assertEquals(expected, clean);
		//Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}
	
	@Test
	public void testObjectListenerNoCloseTag() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");

		String dirty = "<object width=\"320\" height=\"256\" data=\"Vifehandtest10_light_c_Full_.mov\" type=\"video/quicktime\"><param name=\"allowScriptAccess\" value=\"all\"><p>로드하지 못했을 경우 대체 컨텐츠를 입력</p>";
		String expected = "<object width=\"320\" height=\"256\" data=\"Vifehandtest10_light_c_Full_.mov\" type=\"video/quicktime\"><param name=\"allowScriptAccess\" value=\"never\"><p>로드하지 못했을 경우 대체 컨텐츠를 입력</p>";
		String clean = filter.doFilter(dirty);
		System.out.println("dirty    : " + dirty);
		System.out.println("expected : " + expected);
		System.out.println("clean    : " + clean);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testOnlyObjectCloseTag() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		
		String dirty = "</object>";
		String expected = "</object>";
		String clean = filter.doFilter(dirty);
		System.out.println("dirty    : " + dirty);
		System.out.println("expected : " + expected);
		System.out.println("clean    : " + clean);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * null 테스트
	 */
	@Test
	public void testNull() {
		XssSaxFilter filter = XssSaxFilter.getInstance();
		System.out.println("filter.getConfig() : "  + filter.getConfig());
		Assert.assertNotNull(filter.getConfig());
		Assert.assertEquals("", filter.doFilter(null));
		//Assert.assertEquals("", filter.doFilter(null, null, null));
		//Assert.assertNotNull(filter.doFilter("embeded", "param", "param"));
	}

	/**
	 * lucy-xss-superset.xml <notAllowedPattern><![CDATA[&[#\\%x]+[\da-fA-F][\da-fA-F]+]]></notAllowedPattern> 수정
	 * 그 결과 COLOR 색상표(#16진수)는 필터링하지 않는다. 
	 */
	@Test
	public void testSuperSetFix() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String clean = "<TABLE class=\"NHN_Layout_Main\" style=\"TABLE-LAYOUT: fixed\" cellSpacing=\"0\" cellPadding=\"0\" width=\"743\">" + "</TABLE>" + "<SPAN style=\"COLOR: #66cc99\"></SPAN>";
		String filtered = filter.doFilter(clean);
		Assert.assertEquals(clean, filtered);
	}

	@Test
	//EndTag가 없는 HTML이 입력으로 들어왔을 때 필터링한다. (WhiteList File의 Element 속성 EndTag 값이 true 인 경우)
	public void testEndTagFilter() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<p><FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">" + "<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">" + "<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT></FONT></P>";
		String clean = filter.doFilter(dirty);
		String unexpected = dirty;
		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		Assert.assertNotSame(unexpected, clean);
	}

	/**
	 * HTML5 적용된 브라우저에서 Base64 인코딩된 XSS 우회 공격을 필터링한다.
	 */
	@Test
	public void testBase64DecodingTest() {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		String dirty = "<embed src=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\">";
		String expected = "<!-- Not Allowed Attribute Filtered ( src=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\") --><embed invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		String dirty2 = "<object data=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\"></object>";
		String expected2 = "<!-- Not Allowed Attribute Filtered ( data=\"data:text/html;base64,c2NyaXB0OmFsZXJ0KCdlbWJlZF9zY3JpcHRfYWxlcnQnKQ==\") --><object><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}
	
	/**
	 * Element Class의 setName Method와 removeAllAttributes Method를 테스트한다.
	 * IMGLinstener에서 해당 메소드를 호출하여 IMG를 iframe으로 변경하고, IMG의 모든 속성을 제거한 후 원하는 속성으로 변경한다.
	 */
	@Test
	public void testRemoveAllAttributesTest() {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml"); // IMG 태그에 대한 IMGListener 가 설정되어있다.

		String dirty = "<IMG id=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv height=284 src=\"http://thumb.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe_player.jpg\" width=342 movietype=\"1\">";
		
		// IMGListener 에서는 IMG 태그를 iframe 태그로 변경하고, isClosed를 true로 설정한다. 아래는 기존 방식의 결과물.
		String expected = "<iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv?key=></iframe>";
		String clean = filter.doFilter(dirty);
		// (XSS Filter)SAX Parser에서는 IMGListener가 적용은 되지만, 닫는 태그를 검사하지 않는 SAX Parser 특성 상 isClosed를 설정해도, endtag 를 붙여주지 않는다.
		Assert.assertEquals(expected.replace("</iframe>", ""), clean); 

		dirty = "<IMG></IMG>";
		expected = "<iframe></iframe>";
		String actual = filter.doFilter(dirty);
		Assert.assertEquals(expected, actual);
	}

	/**
	 * ASCIICtrl Chars : URL encoded %00 ~ %1F, %7F 이중 문제가 되는 것은 %00 뿐이다.
	 */
	@Test
	public void testASCIICtrlChars() {
		XssSaxFilter filter = XssSaxFilter.getInstance();

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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

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

	/**
	 * VM 옵션 -Xss 128k 에서 overflow 발생하는 사례 / -Xss 256k or Defalut(512k) 옵션에서는 정상 작동
	 * @throws Exception
	 */
	@Test
	public void testCafeHtmlFiltering() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-cafe-child.xml");
		for (String valid : readLines("StackOverFlowError_Sample.html")) {
			String clean = filter.doFilter(valid);
			//Assert.assertTrue("\n" + valid + "\n" + clean, valid.equals(clean));
		}
	}

	/**
	 * 필터링된 Tag와 Attribute 입력에 Comment를 삽입하는 것은 옵션으로한다.
	 * getInstance의 두번째 파라미터가 noComment를 설정할 수 있다.
	 */
	@Test
	public void testNoCommentXssSaxFilter() {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml", true);
		String dirty2 = "<script></script>";
		String expected2 = "&lt;script&gt;&lt;/script&gt;";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}

	/**
	 * DOCTYPE과 xml 태그를 허용하도록한다. 
	 */
	@Test
	public void testDOCTYPEAndXMLELEMNT() {

		XssSaxFilter filter = XssSaxFilter.getInstance();

		String doctype = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">";
		String clean = filter.doFilter(doctype);
		Assert.assertEquals(doctype, clean);

		String xmltag = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		clean = filter.doFilter(xmltag);
		Assert.assertEquals(xmltag, clean);
	}

	/**
	 * override 테스트
	 */
	@Test
	public void testOverrideIssue() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-test.xml");
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

	/**
	 * IEHack을 인식한다 - 설정에 명시 안하면 기본적으로 필터링 된다.
	 */
	@Test
	public void testIEHackTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-default-sax.xml");
		String dirty = "<!--[if !mso]><h1>Hello</h1><![endif]-->";
		//String dirty = "<!--[if gte mso 9]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String expected = "<!--[if !mso]><h1>Hello</h1><![endif]-->";
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

	/**
	 * IEHack을 인식한다 - 설정에 명시 하면, 필터링 하지 않는다.
	 * IEHack EndTag는 <!--[endif]-->, <![endif]--> 2개를 인식한다.
	 * <!--[endif]-->로 들어 올 경우 <![endif]--> 로 교정한다.
	 */
	@Test
	public void testIEHackTagOtherCase() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String Expected = "<!--[if !supportMisalignedColumns]><h1>Hello</h1><![endif]-->";
		Assert.assertEquals(Expected, clean);

		clean = filter.doFilter(Expected);
		Assert.assertEquals(Expected, clean);
	}
	
	/**
	 * IEHack - 주석 안에서의 이스케이프 된 IEHack 태그는 인식하지 않는지 테스트
	 */
	@Test
	public void testIEHackTagInComment() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		String clean = filter.doFilter(dirty);
		
		String Expected = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		Assert.assertEquals(Expected, clean);
	}

	/**
	 * IEHack - 비표준화 IEHack를 표준화하는 작업을 테스트 한다.
	 */
	@Test
	public void testIEHackExtensionElement() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<!--[if !mso]--><p>test</p><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><p>test</p><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	/**
	 * IEHack - 다른 태그 안에서 IEHack 는 필터링 되지 않는다.(부모 자식 간의 관계 검사 X)
	 */
	@Test
	public void testIEHackTagInTheOtherTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<div><!--[if !mso]><p>test</p><![endif]--></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(dirty, clean);
	}

	/**
	 * IEHack - IEHack 태그에 공백 허용 테스트
	 * 상기 testIEHackExtensionElement 테스트에 더해, IEHack 태그에 공백이 들어가는 경우도 기존 IEHack과 동일하게 처리 되는지를 테스트한다.
	 */
	@Test
	public void testIEHackExtensionElementWithSpace() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<!--        [if !mso]  ><style></style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><blocking_style></blocking_style><![endif]-->";
		System.out.println(expected);
		System.out.println(clean);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * IEHack -  Close 태그가 없거나 broken 일 때, IEHack Start 태그 제거하는 메일팀 요구사항 스펙 아웃
	 * 아래 스펙 불가.
	 * SAX 구조상 닫는 태그 또는 well-formed 하지 않은 닫는 태그를 구별한 후 여는 태그를 지운다거나 하는 작업이 쉽지 않음.
	 * 불가능한 것은 아니나, 비용이 큼. 있는 그데로 노출하고 브라우저에서 보여주도록.
	 */
	@Test
	public void testIEHackTagWithoutCloseTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");

		// IE Hack 에서는 Close 태그가 없으면 주석으로 인식되서 뒤에 있는 엘리먼트들 노출에 문제가 생길 수 있다. Close 태그가 없거나 broken 일 때 IE Hack Start 태그를 제거하는 식으로 변경하자.
		String dirty = "<!--[if !IE]><h1>abcd</h1>";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !IE]><h1>abcd</h1>";
		Assert.assertEquals(expected, clean); // end tag 검사하지 않아 필터링 없이 그데로 출력됨.

		dirty = "<!--[if !IE]><h1>abcd</h1><![endif]--"; // <!--[if !IE]>는 그데로 노출되고, <![endif]-- 는 일반 텍스트로 인식 되어 필터링 된다.
		clean = filter.doFilter(dirty);
		expected = "<!--[if !IE]><h1>abcd</h1>&lt;![endif]--";
		Assert.assertEquals(expected, clean);
		
		// 아래는 정상적인 케이스
		dirty = "<!--[if]><h1>abcd</h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = dirty; // 기존과 달리 IEHack 태그 안의 콘텐츠를 제거하는 기능이 막혀, "<!--[if]><![endif]-->"  가 될 수 없음.
		Assert.assertEquals(expected, clean);

	}

	/**
	 * IEHack - 여러가지 grammar 테스트
	 */
	@Test
	public void testIEHackTagWrongGrammar() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
		String dirty = "<!--[if !IE><h1></h1><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !IE><h1></h1><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if><h1></h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if><h1></h1><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if]><h1></h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><h1></h1><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[ifaa><h1></h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[ifaa><h1></h1><![endif]-->";
		Assert.assertEquals(expected, clean);
	}

	/**
	 * White Url을 포함하지 않은 src Attribute 에 대한 보안 필터링 하는지 검사한다.
	 * @throws Exception
	 */
	@Test
	public void testAttributeSrcListener() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-attribure-listener.xml");

		String dirty = "<IMG src=\"http://medlabum.com/cafe/0225/harisu.jpg\" width=\"425\" height=\"344\">";
		String expected = "<IMG src=\"\" width=\"425\" height=\"344\">";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));

		dirty = "<iframe src=\"http://test.com/hello.nhn\" width=\"425\" height=\"344\">";
		expected = "<!-- Not Allowed Tag Filtered -->&lt;iframe src=\"\" width=\"425\" height=\"344\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
	}

	/**
	 * removeTag 속성 테스트
	 */
	@Test
	public void testElementRemoveSimple() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-blog-removetag.xml");

		String dirty = "<html><head></head><body><p>Hello</p></body>";
		String expected = "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * removeTag 속성 테스트 - removeTag 속성 및 ContentsRemoveListener 기능을 테스트한다.
	 * SAX 스펙상 자식 콘텐츠를 삭제하는 ContentsRemoveListener 기능이 동작하지 않아야 한다.
	 */
	@Test
	public void testElementRemoveBlogRequest() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-blog-removetag.xml");
		String dirty = "<html><head><style>P {margin-top:2px;margin-bottom:2px;}</style></head><body><div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div></body></html>";
		String expected = "<!-- Removed Tag Filtered (html) --><!-- Removed Tag Filtered (head) --><!-- Removed Tag Filtered (body) --><div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertNotSame(expected, clean);
	}

	/**
	 * removeTag 속성 테스트
	 */
	@Test
	public void testElementRemoveOPTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-blog-removetag.xml");

		String dirty = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span></p>";
		String expected = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font></span></p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * removeTag 속성 테스트
	 */
	@Test
	public void testElementRemoveOPTagSimple() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-blog-removetag.xml");

		String dirty = "<o:p><font size=\"2\" face=\"바탕\"></font></o:p>";
		String expected = "<!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * removeTag 속성 테스트
	 */
	@Test
	public void testElementRemoveOPTagSimple2() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-blog-removetag.xml");

		String dirty = "<span><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span>";
		String expected = "<span><!-- Removed Tag Filtered (o:p) --><font size=\"2\" face=\"바탕\"></font></span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 *  한글은 태그가 아닌 텍스트로 인식해서 블로킹 prefix 를 붙이지 않고, escape 처리.
	 */
	@Test
	public void testKoreanTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");

		String dirty = "<하하하>";
		String expected = "&lt;하하하&gt;"; // 한글은 태그가 아닌 텍스트로 인식해서 블로킹 prefix를 붙이지 않고, escape 처리.
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 태그간의 관계는 체크하지 않는다. span 태그 안에 div 태그가 와도 필터링 하지 않는다.
	 */
	@Test
	public void NoTagRelation() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<span><div><h1>div테스트</h1></div></span>";
		String expected = "<span><div><h1>div테스트</h1></div></span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * (블로그개발팀)div, table, embed 태그를 다른 모든 태그에서 사용할 수 있다.
	 */
	@Test
	public void testAgreeDivOnAnyWhereFail() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<span><div><h1>div테스트</h1></div></span>";
		String expected = dirty;
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementNaming() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");

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

		dirty = "<:a>";
		expected = "<blocking_:a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<a b>";
		expected = "<!-- Not Allowed Attribute Filtered ( b) --><a>"; // SAX 방식과 기존 결과 차이 발생
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<!a>"; // 요놈은 태그(엘리먼트)로 인식하면 안된다.
		expected = "&lt;!a&gt;"; // 태그가 아닌 텍스트로 인식해서 블로킹 prefix를 붙이지 않고, escape 처리.
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	/**
	 * 외부에서 Writer를 제어할 수 있는 메소드 추가 테스트 - 메일웹개발팀 김형기 수석님 기능 요구사항
	 * case1 StringWriter
	 * @throws Exception 
	 */
	@Test
	public void externalWriterHandlingMethodAddTestStringWriter() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance();
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
		XssSaxFilter filter = XssSaxFilter.getInstance();
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
		XssSaxFilter filter = XssSaxFilter.getInstance();
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

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
	
	/**
	 * 허용되지 않은 엘리먼트는 이스케이프 된다.
	 */
	@Test
	public void elementVsAttributeDisable1() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<body text='test'><p>Hello</p></body>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;body text='test'&gt;<p>Hello</p>&lt;/body&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * 특정 태그(p)에 올 수 있는 속성에 제한을 두지 않는다. 즉 허용된 속성은 어느 태그에도 올 수 있다.
	 */
	@Test
	public void elementVsAttributeDisable2() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<p src='test'>Hello</p>";
		String expected = "<!-- Not Allowed Attribute Filtered --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertNotSame(expected, clean);
	}
	
	@Test
	public void elementVsAttributeDisable3() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<body src='test'>Hello</body>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;body src='test'&gt;Hello&lt;/body&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * src에 script 패턴이 존재 시 무조건 필터링 되는 문제 테스트
	 */
	@Test
	public void notAllowedPatternSrcAttribute() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-simple.xml");
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
		
		// exceptionTagList로 예외처리가 되어있고, element 의 속성요소로 설정이 안되어 있어도 자식 속성을 체크하지 않는 SAX 스펙상 통과
		dirty = "<span class='test'></span>";
		expected = dirty;
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<a HREF=\"javascript:alert('XSS');\">";
		String expected = "<!-- Not Allowed Attribute Filtered ( HREF=\"javascript:alert('XSS');\") --><a>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * Link 태그가 escape 되는지 테스트
	 */
	@Test
	public void linkAttackTest() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * STYLE 속성에서 javascript 패턴 존재하는지 테스트
	 */
	@Ignore
	@Test
	public void styleAttackTest() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">";
		String expected = "<!-- Not Allowed Attribute Filtered --><DIV>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	/**
	 * 기존 DOM Parser 방식을 썼을 때와 달리, startTag 없이 endTag 가 올 경우 escape 없이 그데로 노출된다.
	 * 따라서 아래 &lt;/div&gt; 태그는 endTag로서 작용한다. &lt;/div&gt;&lt;div&gt; 의 결과를 원할 경우 별도의 tag 교정기를 사용해야한다. ex) htmlcleaner, tagsoup
	 */
	@Test
	public void endTagWithoutStartTag() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "</div>";
		String expected = "</div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void notNormalTagNameSpace() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "< HelloTag></ HelloTag>";
		String expected = "&lt; HelloTag&gt;&lt;/HelloTag&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void illegalAttributeEnd() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<table width=\"";
		String expected = "<table width=\"\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void html5TagVideo() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<video></video>";
		String expected = "<video></video>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\"></video>";
		expected = dirty;
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<video width=\"320\" height=\"240\" controls=\"controls\"><source src=\"movie.mp4\" type=\"video/mp4\" pubdate=\"\"></video>";
		expected = dirty; // pubdate=\"\" 속성은 html5 표준에서는 video 태그에서 사용할 수 없는 속성이지만, xss sax filter에서는 해당 속성 사용유무만 체크해서 필터링안됨. 
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void html5TagVideoInDiv() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
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
							XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml", index % 2 == 0?false:true); // 짝수면 주석추가, 홀수면 주석생략
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
							XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
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
							XssSaxFilter filter = XssSaxFilter.getInstance(configFile[index % configFile.length]);
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "#Test";
		String clean = filter.doFilter(dirty);
		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		Assert.assertTrue("\n" + dirty + "\n" + clean, dirty.equals(clean));
	}
	
	/**
	 * 속성에 주석 닫는 태그(--&gt;) 있을 경우에 이스케이프가 잘 되는지 확인.
	 * 속성에 주석 닫는 태그가 있으면 주석으로 처리하는 로직이 깨질 수 있어서 방어해야함.
	 * @throws Exception
	 */
	@Test
	public void atributeComment() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<p tt='-->'>Hello</p>";
		String expected = "<!-- Not Allowed Attribute Filtered ( tt='--&gt;') --><p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void noAtribute() throws Exception {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-embed-param-security.xml");
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
	 * url이 object 태그가 아닌 자식 태그인 param 태그의 src, href, movie 이름을 갖는 데이타로 올 경우는 SAX filter에서는 처리 불가. 
	 */
	@Ignore
	@Test
	public void objectListenerParamTagUrlWhitelistAndTypeCheck() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-embed-param.xml");
		
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		
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
	 * 원래는 허용되는 태그인데, 중간에 disable 시킨 태그의 닫는 태그 처리는 어떻게 되나?
	 * 닫는 태그도 이스케이프가 되어야한다.
	 * SAX 방식에서는 불가능해서, 중간에 특정 태그를 disable 시킬 경우 닫는 태그를 이스케이프 시키는 로직이 들어가야한다. ex) object 태그
	 */
	@Test
	public void openCloseTagRuleCheckDisable() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");

		String dirty = "<object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"></object>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;object type=\"text/html\" data=\"http://test.mireene.com/xss.html\"&gt;&lt;/object&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void objectListenerOnSuperset() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<object data=\"http://serviceapi.nmv.naver.com/\"></object>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://serviceapi.nmv.naver.com/\"&gt;&lt;/object&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void embedListenerOnSuperset() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
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
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-test.xml");
		
		String dirty = "<html><head></head><body><!--[if gte vml 1]><v:shapetype id=\"_x0000_t201\"><![if excel]><x:ClientData ObjectType=\"Drop\"> <x:DropLines>123123 8</x:DropLines> </x:ClientData> <![endif]> </v:shape><![endif]--></body></html>";
		String expected = "<html><head></head><body><!--[if gte vml 1]><xv:shapetype id=\"_x0000_t201\"><![if excel]><!-- Not Allowed Attribute Filtered ( ObjectType=\"Drop\") --><xx:ClientData> <xx:DropLines>123123 8</xx:DropLines> </xx:ClientData> <![endif]> </xv:shape><![endif]--></body></html>";

		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void nestedIehack() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
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
	
	/**
	 * Lucy-XSS Sax버전에 char[]를 input으로 받는 doFilter 추가 요청 테스트
	 */
	@Test
	public void charArrayInput() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");

		String dirty = "<p src='test'>Hello</p>";
		String expected = "<!-- Not Allowed Attribute Filtered --><p>Hello</p>";
		Writer writer = new StringWriter();
		filter.doFilter(dirty.toCharArray(), 0, dirty.length(), writer);
		Assert.assertNotSame(expected, writer.toString());
	}
	
	@Test
	public void testBase64EmbedSrc() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		String dirty = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";
		String expected = "<!-- Not Allowed Attribute Filtered ( SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\") --><EMBED type=\"image/svg+xml\" allowScriptAccess=\"never\" invokeURLs=\"false\" autostart=\"false\" allowNetworking=\"internal\"></EMBED>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testObjectTagDataUrlWithParameter() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		String dirty = "<object data=\"http://www.1.com/2.swf?1234\"></object>";
		String expected = "<object data=\"http://www.1.com/2.swf?1234\" type=\"application/x-shockwave-flash\"><param name=\"invokeURLs\" value=\"false\"><param name=\"autostart\" value=\"false\"><param name=\"allowScriptAccess\" value=\"never\"><param name=\"allowNetworking\" value=\"internal\"><param name=\"autoplay\" value=\"false\"><param name=\"enablehref\" value=\"false\"><param name=\"enablejavascript\" value=\"false\"><param name=\"nojava\" value=\"true\"><param name=\"AllowHtmlPopupwindow\" value=\"false\"><param name=\"enableHtmlAccess\" value=\"false\"></object>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testObjectTagDataUrlWithParameterNegative() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-object-param.xml");
		String dirty = "<object data=\"http://www.1.com/2.html?1234\"></object>";
		String expected = "<!-- Not Allowed Tag Filtered -->&lt;object data=\"http://www.1.com/2.html?1234\"&gt;&lt;/object&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void pairQuoteCheck() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<img src=\"http:/><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		String expected = "<img src=\"http:/\"><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='http:/><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src='http:/'><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=http:/'><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src='http:/'><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=http:/\"><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=\"http:/\"><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src=\"><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=\"\"><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='><a target=\" _blank=\"_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/>";
		expected = "<img src=''><a target=\" _blank=\">_blank\" gt=\"gt\" userimg=\"userImg\" onerror=\"alert('XSS')\"/&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void pairQuoteCheckOtherCase() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = "<img src=\"<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
		String expected = "<img src=\"\"><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		dirty = "<img src='<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
		expected = "<img src=''><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void ieHackHasXssCase() {
		XssSaxFilter filter = XssSaxFilter.getInstance();
		String dirty = "<!--[if <img src=x onerror=alert(123) //] -->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if &lt;img src=x onerror=alert(123) //]>";
	
		Assert.assertEquals(expected, clean);
	}
}