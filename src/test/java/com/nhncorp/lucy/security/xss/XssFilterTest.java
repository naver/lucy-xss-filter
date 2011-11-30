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