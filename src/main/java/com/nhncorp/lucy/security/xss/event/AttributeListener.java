/*
 * @(#) ElementListener.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.event;

import java.util.EventListener;

import com.nhncorp.lucy.security.xss.markup.Attribute;

/**
 * 이 인터페이스는 Cross site scripting 코드가 삽입된 Tag 에 대하여 설정 정보 외에 별도의 필터링을 수행하기 위한
 * 메소드를 제공한다.
 *
 * @author Web Platform Development Team
 *
 */
public interface AttributeListener extends EventListener {

	/**
	 * 이 메소드는 특정 {@link com.nhncorp.lucy.security.xss.markup.Attribute Attribute} 에 대해
	 * 설정 정보 외에 별도의 필터링을 수행한다.
	 *
	 * @param attr	{@link com.nhncorp.lucy.security.xss.markup.Attribute Attribute} 객체.
	 */
	public void handleAttribute(Attribute attr);
}
