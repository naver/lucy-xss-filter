/*
 *	Copyright 2014 Naver Corp.
 *
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */
package com.nhncorp.lucy.security.xss;

import static junit.framework.Assert.*;

import java.io.IOException;

import org.junit.Test;

public class FilteringTagInCommentTest {
	@Test
	public void testConfig() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-filteringtagincomment.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testDefaultStrict() throws IOException {
		XssFilter filter = XssFilter.getInstance();
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testNonFiltering() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nofilteringtagincomment.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testConfigFilteringWithListener() throws IOException {
		XssFilter filter = XssFilter.getInstance("lucy-xss-filteringtagincomment-listener.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <img src='http://www.naver.com/test.img'>Listerner Test</img> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=?key=>Listerner Test</iframe> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testConfigSax() throws IOException {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-filteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testStrictSax() throws IOException {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-strictfilteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testDefaultStrictSax() throws IOException {
		XssSaxFilter filter = XssSaxFilter.getInstance();
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. &lt;h1&gt;제목&lt;/h1&gt; &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testNonFilteringSax() throws IOException {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-nofilteringtagincomment-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}

	@Test
	public void testConfigFilteringWithListenerSax() throws IOException {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-filteringtagincomment-listener-sax.xml");
		String dirty = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <img src='http://www.naver.com/test.img'>Listerner Test</img> <SCRIPT SRC=http://xxx/xss.js></SCRIPT> 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		String clean = filter.doFilter(dirty);
		String expected = "<!--주석안에 태그가 있는 경우에요. <h1>제목</h1> <iframe frameborder='no' width=342 height=296 scrolling=no name='mplayer' src='http://local.cafe.naver.com/MoviePlayer.nhn?dir=?key=>Listerner Test</iframe> &lt;SCRIPT SRC=http://xxx/xss.js&gt;&lt;/SCRIPT&gt; 필터링이 필요한가요? 원본을 유지하는게 좋은가요?-->";
		assertEquals(expected, clean);
	}
}
