/*
 * @(#)FilterRepositoryKey.java $version 2012. 4. 20.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

/**
 * @author nbp
 */
class FilterRepositoryKey {
	String fileName;
	boolean withoutComment;
	
	/**
	 * @param fileName
	 * @param withoutComment
	 */
	public FilterRepositoryKey(String fileName, boolean withoutComment) {
		super();
		this.fileName = fileName;
		this.withoutComment = withoutComment;
	}

	/**
	 * @return
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "FilterRepositoryKey [fileName=" + fileName
				+ ", withoutComment=" + withoutComment + "]";
	}

	/**
	 * @return
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((fileName == null) ? 0 : fileName.hashCode());
		result = prime * result + (withoutComment ? 1231 : 1237);
		return result;
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		FilterRepositoryKey other = (FilterRepositoryKey) obj;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		if (withoutComment != other.withoutComment)
			return false;
		return true;
	}
	
	
}
