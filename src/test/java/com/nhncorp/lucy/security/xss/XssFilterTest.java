package com.nhncorp.lucy.security.xss;

import java.util.ArrayList;

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
			//System.out.println(i);
			String clean = filter.doFilter(invalid);
			Assert.assertFalse("\n" + invalid + "\n" + clean, invalid.equals(clean));
//			System.out.println(invalid);
//			System.out.println(clean);
//			System.out.println("/" + i++);
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
	//EngTag에 대해서 CrossTag를 허용한다.
	//e.g. <p><font></p></font> : 이 예제에서 font 는 CrossTag이다.
	public void testCrossTagFilter() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<p><FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">"
			+ "<FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\">"
			+ "<FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT></FONT></p></FONT>";
		String clean = filter.doFilter(dirty);
		String expected = dirty;
		//System.out.println(clean);
		Assert.assertEquals(expected, clean);

		XssFilter filter2 = XssFilter.getInstance("lucy-xss-mine.xml");
		String dirty2 = "<p><FONT style=\"FONT-SIZE: 9pt; FONT-FAMILY: 1144591_9\"></FONT><FONT></p>" + "<FONT>"
			+ "<p><FONT style=\"FONT-SIZE: 10pt; FONT-FAMILY: 1144591_10\"> 에서 탑승하시오.</FONT><FONT></p>"
			+ "</FONT></FONT></FONT>";
		String clean2 = filter2.doFilter(dirty2);
		String expected2 = dirty2;
		//System.out.println(clean);
		Assert.assertEquals(expected2, clean2);
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
	//사용자가 입력한 attribute Value가 quotes로 열고 닫지 않은 경우 강제 삽입한다. 
	public void testDoubleQuote() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String dirty = "<img src=http://ahnj.nhncorp.com/1.gif width=100 height=10>";
		String expected = "<img src=\"http://ahnj.nhncorp.com/1.gif\" width=\"100\" height=\"10\">";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);

		//attribute Value를 닫기만 한 경우 여는 quote를 강제 삽입한다.
		String dirty2 = "<img src=http://ahnj.nhncorp.com/1.gif\" width=100\' height=10`>";
		String expected2 = "<img src=\"http://ahnj.nhncorp.com/1.gif\" width=\'100\' height=`10`>";
		String clean2 = filter.doFilter(dirty2);
		Assert.assertEquals(expected2, clean2);

		//attribute Value를 열기만 한 경우는 처리하지 않는다. 
		String dirty3 = "<img src=\"http://ahnj.nhncorp.com/1.gif width=\'100 height=`10>";
		String expected3 = "<img src=\"http://ahnj.nhncorp.com/1.gif width=\'100 height=`10>";
		String clean3 = filter.doFilter(dirty3);
		Assert.assertEquals(expected3, clean3);
	}
	
	@Test
	//사용자가 입력한 attribute Value가 quotes로 열고 닫지 않은 경우 강제 삽입한다. 
	public void testWithOnlyEndQuoteTokenize() {
		
		XssFilter filter = XssFilter.getInstance("lucy-xss-mine.xml");
		String dirty ="<img src=ttp://xcuter.pe.kr/1.gif width=1\"%0bonerror='alert(4)'height=10>";
		String expected ="<img src=\"ttp://xcuter.pe.kr/1.gif\" width=\"1\">%0bonerror='alert(4)'height=10&gt;";
		String clean = filter.doFilter(dirty);
		Assert.assertEquals(expected, clean);
	}
}