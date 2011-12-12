/*
 * @(#) XssFilterTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import java.net.URLDecoder;

import org.junit.Assert;
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

	@Test
	// 정상적인 HTML 페이지를 통과 시키는지 검사한다.(필터링 전후가 동일하면 정상)
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		for (String valid : readString(NORMAL_HTML_FILES)) {
			String clean = filter.doFilter(valid);
			Assert.assertTrue("\n" + valid + "\n" + clean, valid.equals(clean));
		}
	}

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
		XssFilter filter = XssFilter.getInstance("lucy-xss-mine.xml");
		for (String invalid : readString(INVALID_HTML_FILES)) {
			String clean = filter.doFilter(invalid);
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
		XssFilter sameFilter = XssFilter.getInstance("lucy-xss.xml");
		XssFilter otherFilter = XssFilter.getInstance("lucy-xss2.xml");

		String dirty = "<applet><!-- abc --></applet>";

		String clean = filter.doFilter(dirty);
		String sameClean = sameFilter.doFilter(dirty);
		String otherClean = otherFilter.doFilter(dirty);

		System.out.println("dirty : " + dirty);
		System.out.println("clean : " + clean);
		System.out.println("sameClean : " + sameClean);
		System.out.println("otherClean : " + otherClean);

		Assert.assertFalse("\n" + dirty + "\n" + clean, dirty.equals(clean));
		Assert.assertTrue("\n" + clean + "\n" + sameClean, clean.equals(sameClean));
		Assert.assertFalse("\n" + clean + "\n" + otherClean, clean.equals(otherClean));
	}

	@Test
	// White Url을 포함하지 않은 Embed 태그에 대한 보안 필터링 하는지 검사한다.
	public void testEmbedListener() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss3.xml");

		String dirty = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\">";
		String expected = "<EMBED src=\"http://medlabum.com/cafe/0225/harisu.wmv\" width=\"425\" height=\"344\" invokeURLs=\"false\" autostart=\"false\" allowScriptAccess=\"never\" allowNetworking=\"internal\">";
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
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
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

		XssFilter filter = XssFilter.getInstance("xss.xml");
		String dirty = "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnZW1iZWRfc2NyaXB0X2FsZXJ0Jyk8L3NjcmlwdD4=\">";
		String expected = "<!-- Not Allowed Attribute Filtered --><embed>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		String dirty2 = "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnb2JqZWN0X3NjcmlwdF9hbGVydCcpPC9zY3JpcHQ+\"></object>";
		String expected2 = "<!-- Not Allowed Attribute Filtered --><object></object>";
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

		Assert.assertTrue(dirty.equals(clean));

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
		String dirty = "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnZW1iZWRfc2NyaXB0X2FsZXJ0Jyk8L3NjcmlwdD4=\"></embed>";
		String expected = "<embed></embed>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		String dirty2 = "<script></script>";
		String expected2 = "&lt;script&gt;&lt;/script&gt;";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}

	@Test
	public void testDetectedBase64EncodingAttect() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo.xml");

		String dirty = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";

		String clean = filter.doFilter(dirty);
		String expected = "<!-- Not Allowed Attribute Filtered --><EMBED type=\"image/svg+xml\"></EMBED>";
		Assert.assertEquals(expected, clean);
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
		String expected = "<style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if !IE]><-->";
		clean = filter.doFilter(dirty);
		expected = "&lt;--&gt;";
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
		String expected = "<div><p>test</p></div>";
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
		String expected = "<h1>abcd</h1>";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if]><h1>abcd</h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><![endif]-->";
		Assert.assertEquals(expected, clean);

		dirty = "<!--[if !IE]><h1>abcd</h1><![endif]--";
		clean = filter.doFilter(dirty);
		expected = "<h1>abcd</h1>&lt;![endif]--";
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
		String expected = "<p>Hello</p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveBlogRequest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");
		String dirty = "<html><head><style>P {margin-top:2px;margin-bottom:2px;}</style></head><body><div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div></body></html>";
		String expected = "<div style=\"font-size:10pt; font-family:gulim;\"><div style=\"padding:0 0 0 10pt\"><p style=\"\">한글테스트에용~~~&nbsp;</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~한글테스트에용~~~</p><p style=\"\">한글테스트에용~~~한글테스트에용~~~</p><p style=\"font-size:pt; font-family:,AppleGothic,sans-serif\"><img class=\"NHN_MAIL_IMAGE\" src=\"http://postfiles2.naver.net/20111116_241/youreme_dev_1321429196418_lRlJSu_jpg/h_cafe_mail.jpg?type=w3\"><br></p><p style=\"font-size:10pt;FONT-FAMILY: Gulim,AppleGothic,sans-serif;padding:0 0 0 0pt\"><span>-----Original Message-----</span><br><b>From:</b> \"박태민\"&lt;youreme_dev@naver.com&gt; <br><b>To:</b> youreme_dev@naver.com<br><b>Cc:</b> <br><b>Sent:</b> 11-11-11(금) 10:24:55<br><b>Subject:</b> test.txt<br /></p></div></div>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveOPTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span></p>";
		String expected = "<p style=\"margin: 0cm 0cm 0pt;\" class=\"MsoNormal\"><span lang=\"EN-US\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><font size=\"2\" face=\"바탕\"></font></span></p>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveOPTagSimple() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<o:p><font size=\"2\" face=\"바탕\"></font></o:p>";
		String expected = "<font size=\"2\" face=\"바탕\"></font>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testElementRemoveOPTagSimple2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-removetag.xml");

		String dirty = "<span><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span>";
		String expected = "<span><font size=\"2\" face=\"바탕\"></font></span>";
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

	@Test
	public void blogBase64NoSuchMethodError() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-blog-NoSuchMethodError.xml");

		String dirty = "<div style=\"font-size:10pt; font-family:'2820191_10';\" class=\"view\"><img src=\"data:image/png;base64,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\" class=\"__se_object\" s_type=\"attachment\" s_subtype=\"image\" jsonvalue=\"%7B%7D\">만ㅇ러ㅣ마넝라ㅓ미나어리ㅏ먼이라ㅓ민아ㅓ리마ㅓㄴ아ㅣ러마ㅣㄴ얼</div>";
		String expected = "<span><!-- Not Allowed Tag Filtered -->&lt;div&gt;<h1>div테스트</h1>&lt;/div&gt;</span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void blogBase64NoSuchMethodError2() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-post-rule.xml");

		String dirty = "<div style=\"font-size:10pt; font-family:'2820191_10';\" class=\"view\"><img src=\"data:image/png;base64,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\" class=\"__se_object\" s_type=\"attachment\" s_subtype=\"image\" jsonvalue=\"%7B%7D\">만ㅇ러ㅣ마넝라ㅓ미나어리ㅏ먼이라ㅓ민아ㅓ리마ㅓㄴ아ㅣ러마ㅣㄴ얼</div>";
		String expected = "<span><!-- Not Allowed Tag Filtered -->&lt;div&gt;<h1>div테스트</h1>&lt;/div&gt;</span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void blogOpTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");

		String dirty = "<span><o:p><font size=\"2\" face=\"바탕\"></font></o:p></span>";
		String expected = "<span><font size=\"2\" face=\"바탕\"></font></span>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

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

		dirty = "<:a>";
		expected = "<blocking_:a>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<a b>";
		expected = "<blocking_a b>";
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<!a>"; // 요놈은 태그(엘리먼트)로 인식하면 안된다.
		expected = "&lt;!a&gt;"; // 태그가 아닌 텍스트로 인식해서 블로킹 prefix를 붙이지 않고, escape 처리.
		clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void mailDisableVerifyRequest() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mailteam-body-test.xml");

		String dirty = "<base href=\"x-msg://171/\" />";
		String expected = "<xbase href=\"x-msg://171/\" />";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		dirty = "<base href=\"x-msg://171/\" abc=\"abcd\" />";
		expected = "<xbase href=\"x-msg://171/\" abc=\"abcd\" />";
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
		Assert.assertEquals("\"", clean3);

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
}