/*
 * @(#)LucyXssFilter.java $version Jan 22, 2013
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

import java.io.Writer;

/**
 * @author nbp
 */
public interface LucyXssFilter {

	String doFilter(String dirty);
	void doFilter(String dirty, Writer writer);
	
}
