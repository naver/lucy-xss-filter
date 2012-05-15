/*
 * @(#) Content.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;

/**
 * 이 클래스는 Markup 언어로 표현된 Content 를 나타내는 Abstract super class 이다.
 * <p>
 * 이 클래스를 상속받는 모든 클래스들의 상속구조는 다음과 같다.
 * <ul>
 * 	<li>{@link Content Content}
 * 		<ul>
 * 			<li>{@link Comment Comment}</li>
 * 			<li>{@link Element Element}</li>
 * 			<li>{@link Text Text}</li>
 * 		</ul>
 * 	</li>
 * </ul>
 * </p>
 * 
 * @author Web Platform Development Team
 * 
 */
public abstract class Content {
	/**
	 * 이 멤버 변수는 Content 의 부모 Element 를 나타낸다. 
	 */
	protected Element parent;

	/**
	 * 이 메소드는 부모 Element 를 리턴한다.
	 * 
	 * @return	부모 Element.
	 */
	public Element getParent() {
		return this.parent;
	}

	/**
	 * 이 메소드는 부모 Element 를 세팅한다.
	 * 
	 * @param parent	부모 Element
	 */
	public void setParent(Element parent) {
		this.parent = parent;
	}

	/**
	 * 이 메소드는 직렬화를 수행한다. {@link #toString() toString()} 과는 달리 직렬화를 위해 사용한다.
	 * <br/><br/>
	 * {@link Element Element}를 제외한 모든 {@link Content Content} 들에 대해
	 * '<'과 '>'을 각각 {@code '&lt;', '&gt;'}으로 변환한다.
	 * 
	 * @param writer	Writer 객체.
	 * @throws IOException	I/O 에러 발생 시.
	 */
	public abstract void serialize(Writer writer) throws IOException;

	/**
	 * 이 메소드는 Content 를 String 으로 표현한다.
	 */
	public String toString() {
		StringWriter writer = new StringWriter();
		try {
			this.serialize(writer);
		} catch (IOException ioe) {
		}

		return writer.toString();
	}
}
