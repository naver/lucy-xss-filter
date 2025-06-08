# **Deprecated**

OWASP Java HTML Sanitizer is recommended as an alternative.

https://owasp.org/www-project-java-html-sanitizer/

----------------

[![logo](images/logo/LUCYXSS_792x269px_white.jpg)](https://github.com/naver/lucy-xss-filter)

## Lucy-XSS : XssFilter, XssPreventer  
Lucy-XSS is an open source library of two defense modules to protect Web applications from XSS attacks. It supports the white-list rule based security policy. The current default rule is Naver's standard. You can change the default rule if you want.


## XssFilter
- Java-based library that supports the method of setting the white-list to protect the web application.
- If you use the filter with the white-list method, it will provide tighter security measures for websites from XSS attacks than the existing filter that uses the black-list method.
- Support for both DOM and SAX Parser.

![Lucy-XSS Filter structure.jpg](images/XssFilter_Structure.png)

## XssPreventer
- Use the apache-common-lang3 library to prevent XSS attack.
- Simply convert all input string as follows so it can't be recognized as HTML tags on web browser.

```
< → &lt; 
> → &gt; 
" → &quot; 
' → &#39;
```

> https://commons.apache.org/proper/commons-lang/javadocs/api-3.1/org/apache/commons/lang3/StringEscapeUtils.html#escapeHtml4%28java.lang.String%29

## XssFilter VS XssPreventer
- Simple text parameter other than HTML should be filtered using the XssPreventer.
- Use Xss Filter if you need to receive HTML tags for input. (eg:  mail, visitors' book,  message board service)


## Release Information
The latest stable release of lucy-xss is 1.6.3. You can pull it from the central Maven repositories.

```xml
<dependency>
	<groupId>com.navercorp.lucy</groupId>
	<artifactId>lucy-xss</artifactId>
	<version>1.6.3</version>
</dependency>
```


## Usage examples
* XssPreventer

``` java
@Test
public void testXssPreventer() {
	String dirty = "\"><script>alert('xss');</script>";
	String clean = XssPreventer.escape(dirty);

	assertEquals(clean, "&quot;&gt;&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;");
	assertEquals(dirty, XssPreventer.unescape(clean));
}
```

* XssFilter : SAX

``` java
@Test
public void testSuperSetFix() {
	XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
	String dirty = "..."; // omitted
	String expected = "<TABLE class=\"Naver_Layout_Main\" style=\"TABLE-LAYOUT: fixed\" cellSpacing=\"0\" cellPadding=\"0\" width=\"743\">" + "</TABLE>" + "<SPAN style=\"COLOR: #66cc99\"></SPAN>";
	String actual = filter.doFilter(dirty);
	assertEquals(expected, actual);
}
```

* XssFilter : DOM

``` java
@Test
public void pairQuoteCheckOtherCase() {
	XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
	String dirty = "<img src=\"<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
	String expected = "<img src=\"\"><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
	String actual = filter.doFilter(dirty);
	assertEquals(expected, actual);
		
	dirty = "<img src='<img src=1\\ onerror=alert(1234)>\" onerror=\"alert('XSS')\">";
	expected = "<img src=''><!-- Not Allowed Attribute Filtered ( onerror=alert(1234)) --><img src=1\\>\" onerror=\"alert('XSS')\"&gt;";
	actual = filter.doFilter(dirty);
	assertEquals(expected, actual);
}
```

For more information, please see User guide

* [Korean Guide](http://naver.github.io/lucy-xss-filter/kr/) 

## Contributing to Lucy-XSS
Want to hack on Lucy-XSS? Awesome! There are instructions to get you started here.
They are probably not perfect, please let us know if anything feels wrong or incomplete.
(Please wait. We are preparing for contribution guide.)

## Other Lucy-XSS Related Projects

- [lucy-xss-servlet-filter](https://github.com/naver/lucy-xss-servlet-filter) : java servlet filter library to protect Web applications from XSS attacks.

## Licensing
Lucy is licensed under the Apache License, Version 2.0. See LICENSE for full license text.

## Maintainer
[![leeplay](https://avatars1.githubusercontent.com/u/7857613?v=2&s=100)](https://github.com/leeplay)
[![Seongmin Woo](https://avatars2.githubusercontent.com/u/1201462?v=3&s=100)](https://github.com/seongminwoo)
[![Jaehee Ahn](https://avatars3.githubusercontent.com/u/3446448?v=3&s=100)](https://github.com/JaeHeeAhn)
