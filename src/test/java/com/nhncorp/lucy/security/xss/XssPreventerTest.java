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

import org.junit.Assert;
import org.junit.Test;


/**
 * {@link XssPreventer} 기능 점검을 위한 테스트 코드.
 *
 * 공격적인 코드와 완전하지 않은 HTML을 필터링 하는지와, 정상적인 HTML을 원형 그대로 보존하는지 검사한다.
 *
 * @author Web Platform Development Team
 */
public class XssPreventerTest {
	
	// 시스템을 공격하는 코드를 필터링 하는지와 원복했을 때 복구가 정상적으로 되는지 검사한다.
	@Test
	public void testXssPreventer() {
		String dirty = "\"><script>alert('xss');</script>";
		String clean = XssPreventer.escape(dirty);
		
		Assert.assertEquals(clean, "&quot;&gt;&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;");
		Assert.assertEquals(dirty, XssPreventer.unescape(clean));
	}

	//한글 유니코드 인코딩 여부 테스트
	@Test
	public void testXssPreventerUnicode() {
		String dirty = "\"><script>alert('이형규');</script>";
		String clean = XssPreventer.escape(dirty);
		
		Assert.assertEquals(clean, "&quot;&gt;&lt;script&gt;alert(&#39;이형규&#39;);&lt;/script&gt;");
		Assert.assertEquals(dirty, XssPreventer.unescape(clean));
	}
	
	// 추가된 ' escape 테스트
	@Test
	public void testXssPreventerSingleQuote() {
		String dirty = "<script>alert('1');</script>";
		String clean = XssPreventer.escape(dirty);
		
		Assert.assertEquals(clean, "&lt;script&gt;alert(&#39;1&#39;);&lt;/script&gt;");
		Assert.assertEquals(dirty, XssPreventer.unescape(clean));
	}
}
