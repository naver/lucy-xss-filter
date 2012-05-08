/*
 * @(#)SecurityUtils.java $version 2012. 5. 4.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss.listener;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;

import com.nhncorp.lucy.security.xss.Constants;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * @author nbp
 */
public class SecurityUtils {
	/**
	 * @param e
	 * @param srcUrl
	 * @param isWhiteUrl
	 * @return
	 */
	public static boolean checkVulnerable(Element e, String srcUrl, boolean isWhiteUrl) {
		boolean isVulnerable = false;
		
		// embed/object 관련 취약성 대응 (XSSFILTERSUS-109)
		if(isWhiteUrl) {
			
		} else {
			String type = e.getAttributeValue("type").trim();
			type = StringUtils.strip(type, "'\"");
			
			if (type != null && type.length() != 0) {
			
				//허용된 type 인가?
				if (!isAllowedType(type)) {
					isVulnerable = true;
				}
			} else {
				//확장자 체크
				srcUrl = StringUtils.strip(srcUrl, "'\"");
				String extension = FilenameUtils.getExtension(srcUrl);
				
				if (StringUtils.isEmpty(extension)) {
					// 확장자가 없어서 MIME TYPE 을 식별할 수 없으면, 그냥 통과시킴. 보안상 hole 이지만 고객 불편을 줄이기 위함.
				} else {
					type = getTypeFromExtension(extension);
					
					//허용된 type 인가?
					if (!isAllowedType(type)) {
						isVulnerable = true;
					} else {
						e.putAttribute("type", "\"" + type + "\"");
					}
				}
				
			}
		}
		return isVulnerable;
	}
	
	/**
	 * @param e
	 * @param srcUrl
	 * @param isWhiteUrl
	 * @return
	 */
	public static boolean checkVulnerableWithHttp(Element e, String srcUrl,
			boolean isWhiteUrl, ContentTypeCacheRepo contentTypeCacheRepo) {
		boolean isVulnerable = false;
		
		// embed/object 관련 취약성 대응 (XSSFILTERSUS-109)
		if(isWhiteUrl) {
			
		} else {
			String type = e.getAttributeValue("type").trim();
			type = StringUtils.strip(type, "'\"");
			
			if (type != null && !"".equals(type)) {
				
				//허용된 type 인가?
				if (!isAllowedType(type)) {
					isVulnerable = true;
				}
			} else {
				//확장자 체크
				srcUrl = StringUtils.strip(srcUrl, "'\"");
				String extension = FilenameUtils.getExtension(srcUrl);
				extension = "";
				
				if (StringUtils.isEmpty(extension)) {
					// 확장자가 없어서 MIME TYPE 을 식별할 수 없으면, 해당 url 을 head HTTP Method 를 이용해 content-type 식별
					type = getContentTypeFromUrlConnection(srcUrl, contentTypeCacheRepo);
					
					//허용된 type 인가?
					if (!isAllowedType(type)) {
						isVulnerable = true;
					} else {
						e.putAttribute("type", "\"" + type + "\"");
					}
					
				} else {
					type = getTypeFromExtension(extension);
					
					//허용된 type 인가?
					if (!isAllowedType(type)) {
						isVulnerable = true;
					} else {
						e.putAttribute("type", "\"" + type + "\"");
					}
				}
				
			}
		}
		return isVulnerable;
	}
	
	public static String getContentTypeFromUrlConnection(String strUrl, ContentTypeCacheRepo contentTypeCacheRepo) {
		// cache 에 먼저 있는지확인.
		String result = contentTypeCacheRepo.getContentTypeFromCache(strUrl);
		//System.out.println("getContentTypeFromCache : " + result);
		if (StringUtils.isNotEmpty(result)) {
			return result;
		}
		
		HttpURLConnection con = null;
		
		try {
			URL url = new URL(strUrl);
			con = (HttpURLConnection)url.openConnection();
			con.setRequestMethod("HEAD");
			con.setConnectTimeout(1000);
			con.setReadTimeout(1000);
			con.connect();
			
			int resCode = con.getResponseCode();
			
			if (resCode != HttpURLConnection.HTTP_OK) {
				System.err.println("error");
			} else {
				result = con.getContentType();
				//System.out.println("content-type from response header: " + result);
				
				if (result!=null) {
					contentTypeCacheRepo.addContentTypeToCache(strUrl, new ContentType(result, new Date()));
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		} finally{
			if(con != null) {
				con.disconnect();
			}
		}
		
		return result;
		
	}
	
	/**
	 * @param extension
	 * @return
	 */
	public static String getTypeFromExtension(String extension) {
		return Constants.mimeTypes.get(extension);
	}

	/**
	 * @param type
	 * @return
	 */
	public static boolean isAllowedType(String type) {
		// embed 태그의 type 속성이 text/* 인가?
		if (StringUtils.isEmpty(type)) {
			return false;
		} else if (StringUtils.startsWith(type, "text/")) {
			return false;
		} else if (StringUtils.isNotEmpty(type) && !Constants.mimeTypes.values().contains(type)) {
			return false;
		} else {
			return true;
		}
	}
}
