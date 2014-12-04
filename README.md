## Lucy-XSS : XssFilter, XssPreventer  
Lucy-XSS to provide a defense library of two ways(XssFilter, XssPreventer) to protect Web applications from XSS attacks. Using the Lucy-XSS Filter, it is possible to apply the security policy of the standard. 
Of course, if you want, it is possible to change the standard of the company. (The current default standard is Navercorp.)

## XssFilter
- Java-based library that supports the method of setting the white-list to protect the web application.
- If you use the White-List method, It is possible to provide a secure Web services than if you use the existing filter that uses the blacklist method.
- Support for both Dom and Sax.

![Lucy-XSS Filter structure.jpg](https://raw.githubusercontent.com/naver/lucy-xss-filter/master/docs/images/XssFilter_Structure.png)

## XssPreventer
- Use the apache-common-lang library to prevent XSS attack.
- The difference between the XssFilter, It is a simple conversion of all strings as follows, so as not to be able to recognize the HTML tag.

```
< → &lt; 
> → &gt; 
" → &quot; 
' → &#39;
```

## Selection criteria of the XssFilter and XssPreventer
- Simple text parameter other than HTML should be filtered using the XssPreventer.
- If html tag is required to user-entered data you need to use the XssFilter. (ex:  mail, visitors' book,  message board service)

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
[![leeplay](https://avatars1.githubusercontent.com/u/7857613?v=2&s=100)](https://github.com/leeplay)
[![Seongmin Woo](https://avatars2.githubusercontent.com/u/1201462?v=3&s=100)](https://github.com/seongminwoo)
[![Jaehee Ahn](https://avatars2.githubusercontent.com/u/1201462?v=3&s=100)](https://github.com/JaeHeeAhn)

