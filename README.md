
## Lucy-XSS : XssFilter, XssPreventer  
Lucy-XSS(Cross Site Scripting)는 악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 두 가지 방식의 방어 라이브러리(XssFilter, XssPreventer)를 제공한다.

## XssFilter : 화이트리스트(White List) 설정 방식으로 구현한 Java 기반의 필터 라이브러리
Lucy-XSS(Cross Site Scripting) Filter는 악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 기능을 화이트리스트(White List) 설정 방식으로 구현한 
Java 기반의 필터 라이브러리이다. Lucy-XSS Filter를 사용하여 전사 표준 XSS 관련 보안 정책을 적용할 수 있으며, 블랙리스트 방식을 사용하는 기존 필터보다 안전하게 
웹 서비스를 제공할 수 있다.

![Lucy-XSS Filter structure.jpg](https://raw.githubusercontent.com/leeplay/xsstest/master/docs/images/XssFilter_Structure.png)

Lucy-XSS Filter 객체를 생성하면 Configuration Builder는 White List Configuration에 정의된 내용을 바탕으로 White List Object Model을 생성하여 
Lucy-XSS Filter Core로 전달한다. Lucy-XSS Filter Core는 Markup Parser(DOM, SAX 둘 다 지원 )가 필터링 대상 HTML 문자열을 파싱하여 생성한 HTML Object Model을 
White List Object Model과 비교하여 필터링한다.

## XssPreventer : 파라미터 문자열을 변환하는 apache-common-lang 기반의 라이브러리
악의적인 XSS 코드의 위험으로부터 웹 애플리케이션을 보호하는 apache-common-lang기반의 라이브러리이다. 
Lucy-XSS Filter와의 차이점은 Lucy-XSS Preventer는 파라미터가 HTML 태그로 인식할 수 없도록 모든 문자열을 아래처럼 단순 변환한다.

```
< → &lt; 
> → &gt; 
" → &quot; 
' → &#39;
```

## XssFilter, XssPreventer 선택 기준
XSS Filter는 보안에 중점을 두면서도, HTML 태그 또한 정상 동작하도록 하는 White List 방식의 XSS 공격 방어 라이브러리이다. 
XSS Preventer는 파라미터로 받은 문자열을 Escape(<→&lt; >→&gt; "→&quot; '→&#39;) 하는 XSS공격 방어 라이브러리이다. 

즉 HTML이 아닌 단순 텍스트 파라미터에 대해서는 XSS Preventer를 사용해 전체를 Escaping 하는 것이 올바른 대응 방법이고 
게시판, 메일, 방명록 등 HTML 태그 기능이 필요한 서비스는 XSS Filter를 사용해 필터링 하는 것이 효과적인 방법이므로 개발자는 두 가지 상황을 고려해 방어 라이브러리를 사용해야 한다.


## Getting started
We also offer an interactive tutorial for quickly learning the basics of using Lucy-XSS.
For up-to-date install instructions, see the Docs.


## Usage examples
* XssPreventer

``` java
@Test
public void testXssPreventer() {
	String dirty = "\"><script>alert('xss');</script>";
	String clean = XssPreventer.escape(dirty);
		
	Assert.assertEquals(clean, "&quot;&gt;&lt;script&gt;alert(&#39xss&#39);&lt;/script&gt;");
	Assert.assertEquals(dirty, XssPreventer.unescape(clean));
}
```

* XssFilter : dom

``` java
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
```

* XssFilter : sax

``` java
@Test
public void testSuperSetFix() {
	XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
	String clean = "<TABLE class=\"NHN_Layout_Main\" style=\"TABLE-LAYOUT: fixed\" cellSpacing=\"0\" cellPadding=\"0\" width=\"743\">" + "</TABLE>" + "<SPAN style=\"COLOR: #66cc99\"></SPAN>";
	String filtered = filter.doFilter(clean);
	Assert.assertEquals(clean, filtered);
}
```

For more information, please see ....doc

## Contributing to Lucy
Want to hack on Lucy-XSS? Awesome! There are instructions to get you started here.
They are probably not perfect, please let us know if anything feels wrong or incomplete.

## Licensing
Lucy is licensed under the Apache License, Version 2.0. See LICENSE for full license text.

## Maintainer
[![benelog](https://avatars1.githubusercontent.com/u/910151?v=2&s=100)](https://github.com/benelog)[![leeplay](https://avatars1.githubusercontent.com/u/7857613?v=2&s=100)](https://github.com/leeplay)
