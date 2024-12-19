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
package com.nhncorp.lucy.security.xss.listener;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;

import com.nhncorp.lucy.security.xss.Constants;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * @author Naver Labs
 */
public class SecurityUtils {
	/**
	 * 
	 */
	private static final String EXTENSION_PROPERTIES = "xssfilter-extension.properties";
	private final static char[] specialCharArray = "?&=".toCharArray();
	 /**
     * The extension separator character.
     * @since Commons IO 1.4
     */
    public static final char EXTENSION_SEPARATOR = '.';

    /**
     * The Unix separator character.
     */
    private static final char UNIX_SEPARATOR = '/';

    /**
     * The Windows separator character.
     */
    private static final char WINDOWS_SEPARATOR = '\\';
    
    private static Properties props;
    
    static {
    	try {
			props = new Properties();
			props.load(SecurityUtils.class.getClassLoader().getResourceAsStream(EXTENSION_PROPERTIES));
		} catch (Exception e) {
			System.out.println(EXTENSION_PROPERTIES + " 파일을 찾지 못했습니다.");
		}
    }

	
	/**
	 * @param element
	 * @param srcUrl
	 * @param isWhiteUrl
	 * @return
	 */
	public static boolean checkVulnerable(Element element, String srcUrl, boolean isWhiteUrl) {
		boolean isVulnerable = false;

		// embed/object 관련 취약성 대응 (XSSFILTERSUS-109)
		if (isWhiteUrl) {

		} else {
			String type = element.getAttributeValue("type").trim();
			type = StringUtils.strip(type, "'\"");

			if (type != null && type.length() != 0) {

				//허용된 type 인가?
				if (!(isAllowedType(type) || props.values().contains(type))) {
					isVulnerable = true;
				}
			} else {
				//확장자 체크
				String url = StringUtils.strip(srcUrl, "'\"");
				String extension = getExtension(url);
				
				if (StringUtils.containsAny(extension, specialCharArray)) {
					int pos = StringUtils.indexOfAny(extension, specialCharArray);
					if (pos != -1) {
						extension = StringUtils.substring(extension, 0, pos);
					}
				}
				
				if (StringUtils.isEmpty(extension)) {
					// 확장자가 없어서 MIME TYPE 을 식별할 수 없으면, 그냥 통과시킴. 보안상 hole 이지만 고객 불편을 줄이기 위함.
				} else {
					type = getTypeFromExtension(extension);
					
					if (StringUtils.isEmpty(type)) {
						type = props.getProperty(extension);
						
						if(type!=null) {
							type = type.trim();
						}
					}
					
					//허용된 type 인가?
					if (StringUtils.isEmpty(type)) {
						isVulnerable = true;
					} else {
						element.putAttribute("type", "\"" + type + "\"");
					}
				}

			}
		}
		return isVulnerable;
	}

	/**
	 * @param element
	 * @param srcUrl
	 * @param isWhiteUrl
	 * @return
	 */
	public static boolean checkVulnerableWithHttp(Element element, String srcUrl, boolean isWhiteUrl, ContentTypeCacheRepo contentTypeCacheRepo) {
		boolean isVulnerable = false;

		// embed/object 관련 취약성 대응 (XSSFILTERSUS-109)
		if (isWhiteUrl) {

		} else {
			String type = element.getAttributeValue("type").trim();
			type = StringUtils.strip(type, "'\"");

			if (type != null && !"".equals(type)) {

				//허용된 type 인가?
				if (!(isAllowedType(type) || props.values().contains(type))) {
					isVulnerable = true;
				}
			} else {
				//확장자 체크
				String url = StringUtils.strip(srcUrl, "'\"");
				String extension = getExtension(url);
				
				if (StringUtils.containsAny(extension, specialCharArray)) {
					int pos = StringUtils.indexOfAny(extension, specialCharArray);
					if (pos != -1) {
						extension = StringUtils.substring(extension, 0, pos);
					}
				}

				if (StringUtils.isEmpty(extension)) {
					// URLConnection을 통해 Mimetype을 결정하면 SSRF 취약점 / JDK 버전 정보 노출이 발생합니다. 
					// 입력 받은 URL을 통해 Type을 결정하기 힘든 경우, default로 'application/octet-stream'로 설정합니다.
					//type = getContentTypeFromUrlConnection(url, contentTypeCacheRepo);
					type = "application/octet-stream";

					//허용된 type 인가?
					if (!isAllowedType(type)) {
						isVulnerable = true;
					} else {
						element.putAttribute("type", "\"" + type + "\"");
					}

				} else {
					type = getTypeFromExtension(extension);
					
					if (StringUtils.isEmpty(type)) {
						type = props.getProperty(extension);
						
						if(type!=null) {
							type = type.trim();
						}
					}
					
					//허용된 type 인가?
					if (StringUtils.isEmpty(type)) {
						isVulnerable = true;
					} else {
						element.putAttribute("type", "\"" + type + "\"");
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

				if (result != null) {
					contentTypeCacheRepo.addContentTypeToCache(strUrl, new ContentType(result, new Date()));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (con != null) {
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
		// TODO: MIME TYPES 화이트리스 방식의 검사는 서비스의 대응속도를 떨어트린다. 보안이슈를 확인 후 문제가 없다면 향후 제거하자.	
		} else if (StringUtils.isNotEmpty(type) && !Constants.mimeTypes.values().contains(type)) {
			return false;
		} else {
			return true;
		}
	}
	
	/**
     * Gets the extension of a filename.
     * <p>
     * This method returns the textual part of the filename after the last dot.
     * There must be no directory separator after the dot.
     * <pre>
     * foo.txt      --> "txt"
     * a/b/c.jpg    --> "jpg"
     * a/b.txt/c    --> ""
     * a/b/c        --> ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     *
     * @param filename the filename to retrieve the extension of.
     * @return the extension of the file or an empty string if none exists or <code>null</code>
     * if the filename is <code>null</code>.
     */
    public static String getExtension(String filename) {
        if (filename == null) {
            return null;
        }
        int index = indexOfExtension(filename);
        if (index == -1) {
            return "";
        } else {
            return filename.substring(index + 1);
        }
    }
	
	/**
     * Returns the index of the last extension separator character, which is a dot.
     * <p>
     * This method also checks that there is no directory separator after the last dot.
     * To do this it uses {@link #indexOfLastSeparator(String)} which will
     * handle a file in either Unix or Windows format.
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     * 
     * @param filename  the filename to find the last path separator in, null returns -1
     * @return the index of the last separator character, or -1 if there
     * is no such character
     */
    public static int indexOfExtension(String filename) {
        if (filename == null) {
            return -1;
        }
        int extensionPos = filename.lastIndexOf(EXTENSION_SEPARATOR);
        int lastSeparator = indexOfLastSeparator(filename);
        return (lastSeparator > extensionPos ? -1 : extensionPos);
    }
    
    /**
     * Returns the index of the last directory separator character.
     * <p>
     * This method will handle a file in either Unix or Windows format.
     * The position of the last forward or backslash is returned.
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     * 
     * @param filename  the filename to find the last path separator in, null returns -1
     * @return the index of the last separator character, or -1 if there
     * is no such character
     */
    public static int indexOfLastSeparator(String filename) {
        if (filename == null) {
            return -1;
        }
        int lastUnixPos = filename.lastIndexOf(UNIX_SEPARATOR);
        int lastWindowsPos = filename.lastIndexOf(WINDOWS_SEPARATOR);
        return Math.max(lastUnixPos, lastWindowsPos);
    }
}
