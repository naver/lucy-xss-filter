package com.nhncorp.lucy.security.xss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class XssFilterIEHackTest {
	@Test
	//IEHack을 허용한다.
	public void testIEHackTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-default.xml");
		String dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String expected = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		assertEquals(expected, clean);

		dirty = "<!--[if !IE]><-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if !IE]>&lt;--&gt;";
		assertEquals(expected, clean);

		dirty = "<!--> <![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--&gt; &lt;![endif]-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testIEHackTagOtherCase() {
		XssFilter xssFilter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !supportMisalignedColumns]--> <style> div { border:1px solid #f00; } </style><!--[endif]-->";
		String clean = xssFilter.doFilter(dirty);
		String expected = "<!--[if !supportMisalignedColumns]> <style></style><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[if !supportMisalignedColumns]> <style> div { border:1px solid #f00; } </style><![endif]-->";
		clean = xssFilter.doFilter(dirty);
		assertEquals(expected, clean);
	}

	@Test
	public void testIEHackTagInComment() {
		XssFilter xssFilter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		String clean = xssFilter.doFilter(dirty);
		String expected = "<!-- Removed Tag Filtered (&lt;!--[if !mso]--&gt;) -->";
		assertEquals(expected, clean);
	}

	@Test
	//Element Class의 remveAllContents Method를 테스트한다.
	//StyleListener에서 해당 메소드를 호출하여 style 태그의 하위에 속하는 모든 child를 제거한다.
	public void testRemoveAllContents() {

		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		assertEquals(expected, clean);
	}

	@Test
	//IEHack의 비표준을 표준화하여 비표준과 표준의 모두 IEHackExtensionElement로 동일하게 다룬다.
	//Element Class를 extends하였으므로 Element의 모든 기능을 사용할 수 있다. (setName method는 예외로 한다.)
	//이 테스트에서는 비표준을 표준으로 변경하는 기능을 테스트한다.
	//그리고 하위에 속하는 Element들이 적절하게 해당되는 Listener를 타는지 테스트한다.
	//여기서는, 하위의 style element가 StyleListener를 가지도록 설정돼 있다. (@lucy-xss-mail.xml)
	public void testIeHackExtensionElement() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !mso]--><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[if !mso]><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if !mso]><style></style><![endif]-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testIeHackTagInTheOtherTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<div><!--[if !mso]><p>test</p><![endif]--></div>";
		String clean = filter.doFilter(dirty);
		String expected = "<div><!--[if !mso]><p>test</p><![endif]--></div>";
		assertEquals(expected, clean);
	}

	@Test
	//IEHackExtensionElement의 모든 객체는 동일한 Element로 간주된다.
	//그래서, 설정파일에서도 대표 이름 하나로 설정한다.
	//<element name="IEHackExtension">
	//IEHackExtension element가 IEHackExtensionListener 를 가지도록 설정했다. (@lucy-xss-mail2.xml)
	public void testIeHackExtensionElementConfig() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");
		String dirty = "<!--[if !mso]--><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><!--[endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><![endif]-->";
		assertEquals(expected, clean);
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
		assertEquals(expected, clean);
	}

	@Test
	//상기 testIEHackExtensionElement 테스트에 더해, IEHack 태그에 공백이 들어가는 경우도 기존 IEHack과 동일하게 처리 되는지를 테스트한다.
	public void testIEHackExtensionElementWithSpace() {
		//IEHackExtension
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--        [if !mso]  ><style>v\\:* {behavior:url(#default#VML);} o\\:* {behavior:url(#default#VML);} w\\:* {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);} </style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !mso]><style></style><![endif]-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testIEHackTagWithoutCloseTag() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail2.xml");

		// IE Hack 에서는 Close 태그가 없으면 주석으로 인식되서 뒤에 있는 엘리먼트들 노출에 문제가 생길 수 있다. Close 태그가 없거나 broken 일 때 IE Hack Start 태그를 제거하는 식으로 변경하자.
		String dirty = "<!--[if !IE]><h1>abcd</h1>";
		String clean = filter.doFilter(dirty);
		String expected = "<!-- Removed Tag Filtered (&lt;!--[if !IE]&gt;) --><h1>abcd</h1>";
		assertEquals(expected, clean);

		dirty = "<!--[if]><h1>abcd</h1><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[if !IE]><h1>abcd</h1><![endif]--";
		clean = filter.doFilter(dirty);
		expected = "<!-- Removed Tag Filtered (&lt;!--[if !IE]&gt;) --><h1>abcd</h1>&lt;![endif]--";
		assertEquals(expected, clean);
	}

	@Test
	public void testIEHackTagWrongGrammar() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String dirty = "<!--[if !IE><style>abcd</style><![endif]-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--[if !IE><style></style><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[if><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if><style></style><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[if]><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[if]><style></style><![endif]-->";
		assertEquals(expected, clean);

		dirty = "<!--[ifaa><style>abcd</style><![endif]-->";
		clean = filter.doFilter(dirty);
		expected = "<!--[ifaa><style></style><![endif]-->";
		assertEquals(expected, clean);
	}
}
