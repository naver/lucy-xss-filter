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
		int i = 1;
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
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
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
		String clean ="<TABLE class=\"NHN_Layout_Main\" style=\"TABLE-LAYOUT: fixed\" cellSpacing=\"0\" cellPadding=\"0\" width=\"743\">" +
				"</TABLE>" +
				"<SPAN style=\"COLOR: #66cc99\"></SPAN>";
		String filtered = filter.doFilter(clean);
		Assert.assertEquals(clean, filtered);
	}
	
	@Test
	//EndTag가 없는 HTML이 입력으로 들어왔을 때 필터링한다. (WhiteList File의 Element 속성 EndTag 값이 true 인 경우)
	public void testEndTagFilter() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<p><FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">"
			+ "<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">"
			+ "<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT></FONT></P>";
		String clean = filter.doFilter(dirty);
		String unexpected = dirty;
		Assert.assertNotSame(unexpected, clean);
	}		
		
	@Test
	//HTML5 적용된 브라우저에서 Base64 인코딩된 XSS 우회 공격을 필터링한다.
	public void testBase64DecodingTest() {
		
		XssFilter filter = XssFilter.getInstance("xss.xml");
		String dirty ="<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnZW1iZWRfc2NyaXB0X2FsZXJ0Jyk8L3NjcmlwdD4=\">";
		String expected ="<!-- Not Allowed Attribute Filtered --><embed>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		String dirty2 ="<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnb2JqZWN0X3NjcmlwdF9hbGVydCcpPC9zY3JpcHQ+\"></object>";
		String expected2 ="<!-- Not Allowed Attribute Filtered --><object></object>";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}
	
	@Test
	public void testIMGListenerTest(){
		
		XssFilter filter = XssFilter.getInstance("lucy-xss-cafe-child.xml");

		String dirty = "<IMG id=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv height=284 src=\"http://thumb.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe_player.jpg\" width=342 movietype=\"1\">";
		String expected = "<iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=mms://stream.media.naver.com/cafeucc2/2007/8/6/41/46b6e5b82fd46b6e5c23c8-danyecafe.wmv?key=></iframe>";
		String clean = filter.doFilter(dirty);
		Assert.assertTrue("\n" + dirty + "\n" + clean + "\n" + expected, expected.equals(clean));
		
		dirty = "<IMG><font></font></IMG>";
		expected = "<iframe></iframe>";
		String actual = filter.doFilter(dirty);
		Assert.assertEquals(expected, actual);
		
	}
	
	@Test
	public void testASCIICtrlChars(){
		// ASCIICtrl Chars : URL encoded %00 ~ %1F, %7F 이중 문제가 되는 것은 %00 뿐이다.
		XssFilter filter = XssFilter.getInstance();

		String dirty = URLDecoder.decode("%00");
		String expected = "\0";
		String clean = filter.doFilter(dirty);
		
		Assert.assertTrue(expected.equals(clean));
		
		String dirty2="aaa\0aaa";
		String expected2 = "aaa\0aaa";
		String clean2 = filter.doFilter(dirty2);
		
		Assert.assertTrue(expected2.equals(clean2));
		
		String dirty3="\0aaa\0\0aaa\0";
		String expected3 = "\0aaa\0\0aaa\0";
		String clean3 = filter.doFilter(dirty3);
		
		Assert.assertTrue(expected3.equals(clean3));
	
	
	}

	// startTag에서 공백 뒤에 오는 Close char '/' 를 attributeName으로 인식하는 오류 수정
	// e.g. <br />, <img src="aaaa" />
	// 공백 + /> 가 표준이므로 공백 없이 '/' char가 온 경우도 공백을 넣어서 리턴하도록 함.
	// e.g. <br/> -> <br />
	@Test
	public void testXHTMLStandard () {
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
		
		String dirty5 = "<p>"
			+"<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">"
			+"<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT>"
			+"<br />"
			+"</FONT>" 
			+"</p>";
		
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
		String dirty ="<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnZW1iZWRfc2NyaXB0X2FsZXJ0Jyk8L3NjcmlwdD4=\"></embed>";
		String expected ="<embed></embed>";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
		
		String dirty2 ="<script></script>";
		String expected2 ="&lt;script&gt;&lt;/script&gt;";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);
	}

	
	@Test
	public void testDetectedBase64EncodingAttect() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo.xml");
		
		String dirty = "<EMBED SRC=\"data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>";
		
		String clean = filter.doFilter(dirty);
		
		System.out.println(clean);
	}
	
	@Test
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
	public void testIEHackTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-default.xml");
		//String dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String dirty = "<!--[if gte mso 9]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		System.out.println("IEHack :: " + clean);
		Assert.assertEquals(dirty, clean);
		
		
		dirty = "<!--[if !IE]> <-->";
		clean = filter.doFilter(dirty);
		System.out.println("IEHack&comment :  " + clean);
		
		dirty = "<!--> <![endif]-->";
		clean = filter.doFilter(dirty);
		System.out.println("IEHack&comment :  " + clean);
		
		XssFilter filter2 = XssFilter.getInstance("lucy-xss-mail.xml");
		dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		clean = filter2.doFilter(dirty);
		System.out.println("IEHack :: " + clean);
		//Assert.assertEquals(dirty, clean);

	}

	@Test
	public void testOnMouseFilter() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-on.xml");
		
		String dirty =" onmouseover=prompt(954996)";
		String dirty2 = URLDecoder.decode("%22%20onmouseover%3dprompt%28954996%29%20bad%3d%22");
		String dirty3 ="\" onmouseover=prompt(954996)\'aa";
		
		String clean = filter.doFilter("paramT", "paramA", dirty);
		String clean2 = filter.doFilter("paramT", "paramA", dirty2);
		String clean3 = filter.doFilter("paramT", "paramA", dirty3);
		
		System.out.println("clean::::[" + clean + "]");
		System.out.println("clean2::::[" + clean2 + "]");
		System.out.println("clean3::::[" + clean3 + "]");
		
		

		String orgKeyword = dirty2;//dirty3; //keyword 파라미터에 사용자가 입력하는 경우를 예로 든다.
		                
		                XssFilter filter1 = XssFilter.getInstance("lucy-xss-on.xml"); // 새로운 사용자 정의 whitelist file을 만든다 (아래 첨부 내용 참고)
		//이 API 는 version 1.1.0부터 제공합니다. 그 이하 version에서는 기존 방법대로 사용하세요.  단, lucy-xss.xml에 Element와 Attribute정의를 추가해야합니다.              
		                
		                String[] attList = orgKeyword.split("[\"'`]"); 
		                
		                boolean resultflag = true;
		                
		                for(String att : attList){
		                	
		                	att = "\"" + att + "\"";
		                	
		                	String cleanAtt = filter1.doFilter("paramT", "paramA", att); // 공백으로 구분된 입력 값을 각각 필터링한다.
		                	
		                	if (!att.equals(cleanAtt)) {
		                		resultflag = false;
		                	} 
		                }
		                
		               		                
		                if(resultflag){
		                        System.out.println("Clean User!!");
		                }else{
		                        System.out.println("Dirty User !!");
		                }
	}
}