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


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.Writer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * 대용량 파일 처리 시 {@link XssFilter} OOM 분석을 위한 테스트 코드.
 * 메일웹 개발팀 문의 사항.
 * @author Web Platform Development Team
 */
public class XssFilterOOMTest extends XssFilterTestCase {
	private static final String BIG_HTML_FILES_6M = "본문이 큰 html 메일_6M.html";
	private static final String BIG_HTML_FILES_31M = "본문이 큰 html 메일_31M.html";
	private static final String BIG_HTML_FILES_62M = "본문이 큰 html 메일_62M.html";
	private static final String BIG_EML_FILES_8M = "본문이_큰_html_메일.eml";
	private static final String BIG_HTML_FILES_6M_REMOVE_IEHACK = "본문이 큰 html 메일_IEHack제거_6M.html";
	private static final String BIG_HTML_FILES_6M_REMOVE_HTML_BODY_TAG = "본문이 큰 html 메일_6M_remove_html_body_tag.html";
	private static final String BIG_HTML_FILES_3M = "본문이 큰 html 메일_용량줄임.html";
	private static final String BIG_HTML_FILES_1_4_M = "bigHtml_1.4M.html";
	private static final String BIG_HTML_FILES_1_7_M = "bigHtmlxssFilterGuide_1.7M.html";

	@Ignore
	@Test
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_EML_FILES_8M);
		String clean = filter.doFilter(target);
		
	}
	
	@Test
	public void testOnlyOneElementCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = "<h1>Hello</h1>";
		String clean = filter.doFilter(target);
		long total = Runtime.getRuntime().totalMemory();
		long free = Runtime.getRuntime().freeMemory();
		long used = total - free;
		System.out.println("Used memory: " + used);
		System.out.println("clean : " + clean);
	}
	
	@Ignore
	@Test
	public void test6MFileSizeCase() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml", true);
		String target = readString(BIG_HTML_FILES_6M);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test31MFileSizeCase() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String target = readString(BIG_HTML_FILES_31M);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test62MFileSizeCase() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-superset.xml");
		String target = readString(BIG_HTML_FILES_62M);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}

	@Ignore
	@Test
	public void test6MFileSizeCaseConcurrentRun() throws Exception {
		ExecutorService service = Executors.newFixedThreadPool(100);
        final CountDownLatch latch = new CountDownLatch(10);
            for (int i = 0; i < 10; i++) {
                final int index = i;
                service.execute(new Runnable() {
                    public void run() {
                    	XssFilter filter = XssFilter.getInstance();
                		String target = "";
						try {
							target = readString(BIG_HTML_FILES_6M);
							String result = filter.doFilter(target);
						} catch (Exception e) {
						} finally {
							latch.countDown();
						}
                		
                    }
                });
            }
            latch.await();
	}
	
	@Ignore
	@Test
	public void test3MFileSize() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_3M);
		//String result = filter.doFilter(target);
		//Assert.assertTrue(target.equals(result));
		Writer writer;
		writer = new BufferedWriter(new FileWriter("d:/test3MFileSizeForEachTokenWayOldRule.html"));
		//writer = new BufferedWriter(new FileWriter("d:/test3MFileSizeForAllTokenWay2.html"));
		filter.doFilter(target, writer);
	}
	
	@Ignore
	@Test
	public void test6MFileSizeRemoveIEHackCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_6M_REMOVE_IEHACK);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test6MFileSizeRemoveHtmlBodyTagCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_6M_REMOVE_HTML_BODY_TAG);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test62MFileSizeCaseFile() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_62M);
		//filter.doFilter(target);
		Writer writer;
		writer = new BufferedWriter(new FileWriter("d:/test62MFile.html"));
		filter.doFilter(target, writer);
	}
	
	@Ignore
	@Test
	public void test6MFileSizeCaseWithNelo() throws Exception {
		XssFilter filter = XssFilter.getInstance("lucy-xss-nelo.xml");
		String target = readString(BIG_HTML_FILES_6M);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void testBigHtml_1_4_M() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_1_4_M);
		Writer writer;
		writer = new BufferedWriter(new FileWriter("d:/testBigHtml_1_4_M_mem_advanced.html"));
		filter.doFilter(target, writer);
	}
	
	@Ignore
	@Test
	public void testBigHtml_1_7_M() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_1_7_M);
		Writer writer;
		writer = new BufferedWriter(new FileWriter("d:/testBigHtml_1_7_M_mem_advanced.html"));
		filter.doFilter(target, writer);
	}
}