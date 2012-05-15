/*
 * @(#)ContentTypeCache.java $version 2012. 5. 4.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss.listener;

import java.util.Date;

/**
 * @author nbp
 */
public class ContentType {
	private String contentType;
	private Date regdate;
	
	public ContentType(String contentType, Date regdate) {
		super();
		this.contentType = contentType;
		this.regdate = (Date) regdate.clone();
	}
	
	public String getContentType() {
		return contentType;
	}
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}
	public Date getRegdate() {
		return regdate;
	}
	public void setRegdate(Date regdate) {
		this.regdate = regdate;
	}
	
	/**
	 * @return
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "ContentTypeCache [contentType=" + contentType + ", regdate="
				+ regdate + "]";
	}
	
	
}
