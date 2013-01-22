package com.nhncorp.lucy.security.xss;

import java.io.IOException;

import junit.framework.Assert;

import org.junit.Test;


public class FilteringTagInCommentTest {

	@Test
	public void testConfig() throws IOException {

		XssFilter filter = XssFilter.getInstance("lucy-xss-filteringtagincomment.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}

	@Test
	public void testDefaultStrict() throws IOException {

		XssFilter filter = XssFilter.getInstance();
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testNonFiltering() throws IOException {

		XssFilter filter = XssFilter.getInstance("lucy-xss-nofilteringtagincomment.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";

		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testConfigFilteringWithListener() throws IOException {

		XssFilter filter = XssFilter.getInstance("lucy-xss-filteringtagincomment-listener.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <img src='http://www.naver.com/test.img'>Listerner Test</img> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=?key=>Listerner Test</iframe> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testConfigSax() throws IOException {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-filteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testStrictSax() throws IOException {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-strictfilteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testDefaultStrictSax() throws IOException {

		XssSaxFilter filter = XssSaxFilter.getInstance();
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testNonFilteringSax() throws IOException {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-nofilteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";

		Assert.assertEquals(expected, clean);
	}
	
	@Test
	public void testConfigFilteringWithListenerSax() throws IOException {

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-filteringtagincomment-listener-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <img src='http://www.naver.com/test.img'>Listerner Test</img> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		System.out.println(dirty);
		System.out.println(clean);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=?key=>Listerner Test</iframe> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";

		Assert.assertEquals(expected, clean);
	}
}
