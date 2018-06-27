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
package com.nhncorp.lucy.security.xss.markup.rule;

import static junit.framework.Assert.*;

import org.junit.Test;

public class CharArraySegmentTest {
	@Test
	public void testNull() {
		CharArraySegment seg = new CharArraySegment("abb");
		assertNotNull(seg.trim());
		assertEquals(-1, seg.posOf((char[])null));
		assertEquals(-1, seg.lastPosOf((char[])null));
		assertEquals(0, seg.lastPosOf('a'));
	}

	@Test
	public void testConcate() {
		CharArraySegment seg = new CharArraySegment("abc");
		CharArraySegment concated = seg.concate(seg);
		assertEquals("abc", concated.toString());
		//TODO 의도한 동작인지 확인 필요
	}
}
