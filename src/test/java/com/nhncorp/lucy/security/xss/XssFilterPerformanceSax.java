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

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Ignore;
import org.junit.Test;

/**
 * {@link XssFilter} 성능 테스트.
 *
 * 파일의 크기와 반복횟수를 조절해서 성능을 점검한다.
 *
 * @author Web Platform Development Team
 */
public class XssFilterPerformanceSax extends XssFilterTestCase {
	private static final String DEFAULT_SMALL_FILES[] = { "xss-size27k.html"};

	private static final String[] configFile = {"lucy-xss-superset-sax.xml", "lucy-xss-sax-simple.xml", "lucy-xss-superset-sax.xml", "lucy-xss-sax-blog-removetag.xml"};
	private static final String[] targetStringOnOtherConfig = {"<img src='script:/lereve/lelogo.gif' width='700'>", "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->", "<!--[if !supportMisalignedColumns]--><h1>Hello</h1><!--[endif]-->", "<html><head></head><body><p>Hello</p></body>"};

	private static final String BIG_HTML_FILES_6M = "본문이 큰 html 메일_6M.html";
	private static final String BIG_HTML_FILES_31M = "본문이 큰 html 메일_31M.html";
	private static final String BIG_HTML_FILES_40M = "본문이 큰 html 메일_40M.html";
	private static final String BIG_HTML_FILES_62M = "본문이 큰 html 메일_62M.html";
	private static final String BIG_HTML_FILES_3M = "본문이 큰 html 메일_용량줄임.html";
	private static final String BIG_HTML_FILES_1_4_M = "bigHtml_1.4M.html";
	private static final String BIG_HTML_FILES_1_7_M = "bigHtmlxssFilterGuide_1.7M.html";
	private static final String NORMAL_MAIL_HTML_FILES_50k = "normalMail50k.html";

	public void product(int loopCount, String... filePaths) throws Exception {
		XssFilter filter = XssFilter.getInstance();
		for (String text : readString(filePaths)) {
			printPerformance(filter, text, loopCount);
		}
	}

	public static void main(String[] args) throws Exception {
		XssFilterPerformanceSax main = new XssFilterPerformanceSax();
		if (0 != args.length) {
			main.product(0, args);
			return;
		}

		main.product(1000, DEFAULT_SMALL_FILES);
	}

	@Test
	public void stubTest() {
		assertTrue(true);
	}

	@Ignore
	@Test
	public void variousInputVariousConfigLongMultiThreadTestForSimpleData() {
		ExecutorService service = Executors.newFixedThreadPool(100);
		final AtomicInteger errorCounter = new AtomicInteger();
		try {
			int loop = 1000000;
			while(loop-->0) {
				runThreadLongForSimpleData(service, errorCounter);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			service.shutdown();
			System.out.println("errorCount : " + errorCounter);
		}
	}

	@Ignore
	@Test
	public void variousInputVariousConfigLongMultiThreadTestForBigData() {
		ExecutorService service = Executors.newFixedThreadPool(100);
		final AtomicInteger errorCounter = new AtomicInteger();
		try {
			int loop = 10;
			while(loop-->0) {
				runThreadLongForBigData(service, errorCounter);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			service.shutdown();
			System.out.println("errorCount : " + errorCounter);
		}
	}

	@Ignore
	@Test
	public void mailServiceSimulation() {
		ExecutorService service = Executors.newFixedThreadPool(100);
		final AtomicInteger errorCounter = new AtomicInteger();
		try {
			int loop = 1;
			while(loop-->0) {
				runThreadLongForMailSimulation(service, errorCounter);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			service.shutdown();
			System.out.println("errorCount : " + errorCounter);
		}
	}

	@Ignore
	@Test
	public void stackoverflowForManyTagRelationSaxFilter() {
		StringBuffer tagInTag = new StringBuffer();

		int loop = 100000;
		while (loop-->0) {
			tagInTag.append("<div>");
		}

		loop = 100000;
		while (loop-->0) {
			tagInTag.append("</div>");
		}

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = tagInTag.toString();
		filter.doFilter(dirty);
	}

	@Ignore
	@Test
	public void stackoverflowForManyAttributeSaxFilter() {
		StringBuffer tagInTag = new StringBuffer("<div");

		int loop = 100000;
		while (loop-->0) {
			tagInTag.append(" attribute" + loop + "=" + "value");
		}

		tagInTag.append("></div>");

		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-superset-sax.xml");
		String dirty = tagInTag.toString();
		filter.doFilter(dirty);
	}

	/**
	 * @param service
	 */
	private void runThreadLongForSimpleData(ExecutorService service, final AtomicInteger errorCounter) {
		int runCount = 10000;
		final CountDownLatch latch = new CountDownLatch(runCount);
		try {
			for(int i=0; i< runCount; i++) {
				final int index = i;
				service.execute(new Runnable() {

					public void run() {
						try {
							XssSaxFilter filter = XssSaxFilter.getInstance(configFile[index % configFile.length]);
							String dirty = targetStringOnOtherConfig[index % targetStringOnOtherConfig.length];
							filter.doFilter(dirty);
						} catch (Exception e) {
							errorCounter.incrementAndGet();
						} catch (OutOfMemoryError e) {
							e.printStackTrace();
							errorCounter.incrementAndGet();
						} finally {
							latch.countDown();
						}
					}
				});
			}
			latch.await();
		} catch (Exception e) {
			 throw new RuntimeException(e);
		}
	}

	private void runThreadLongForBigData(ExecutorService service, final AtomicInteger errorCounter) {
		int runCount = 10000;
		final CountDownLatch latch = new CountDownLatch(runCount);
		try {
			for(int i=0; i< runCount; i++) {
				final int index = i;
				service.execute(new Runnable() {

					public void run() {
						try {
							XssSaxFilter filter = XssSaxFilter.getInstance(configFile[index % configFile.length]);
							String dirty = "";

							if (index == 0) {
								dirty = targetStringOnOtherConfig[index % targetStringOnOtherConfig.length];
							} else if (index % 9000 == 0) {
								dirty = readString(BIG_HTML_FILES_62M);
							} else if (index % 7000 == 0) {
								dirty = readString(BIG_HTML_FILES_31M);
							} else if (index % 5000 == 0) {
								dirty = readString(BIG_HTML_FILES_6M);
							} else if (index % 3000 == 0) {
								dirty = readString(BIG_HTML_FILES_3M);
							} else if (index % 2000 == 0) {
								dirty = readString(BIG_HTML_FILES_1_7_M);
							} else if (index % 500 == 0) {
								dirty = readString(BIG_HTML_FILES_1_4_M);
							} else {
								dirty = targetStringOnOtherConfig[index % targetStringOnOtherConfig.length];
							}

							filter.doFilter(dirty);
						} catch (Exception e) {
							errorCounter.incrementAndGet();
						} catch (OutOfMemoryError e) {
							e.printStackTrace();
							errorCounter.incrementAndGet();
						} finally {
							latch.countDown();
						}
					}
				});
			}
			latch.await();
		} catch (Exception e) {
			 throw new RuntimeException(e);
		}
	}

	private void runThreadLongForMailSimulation(ExecutorService service, final AtomicInteger errorCounter) throws IOException {
		int runCount = 10000;
		final CountDownLatch latch = new CountDownLatch(runCount);
		final String dirtyNormal = readString(NORMAL_MAIL_HTML_FILES_50k);

		try {
			for(int i=0; i< runCount; i++) {
				final int index = i;
				service.execute(new Runnable() {

					public void run() {
						try {
							XssSaxFilter filter = XssSaxFilter.getInstance(configFile[index % configFile.length]);
							String dirty = "";

							if (index == 0) {
								dirty = dirtyNormal;
							} else if (index % 10000 == 0) {
								dirty = readString(BIG_HTML_FILES_40M);
							} else {
								dirty = dirtyNormal;
							}

							filter.doFilter(dirty);
						} catch (Exception e) {
							errorCounter.incrementAndGet();
						} catch (OutOfMemoryError e) {
							e.printStackTrace();
							errorCounter.incrementAndGet();
						} finally {
							latch.countDown();
						}
					}
				});
			}
			latch.await();
		} catch (Exception e) {
			 throw new RuntimeException(e);
		}
	}
}