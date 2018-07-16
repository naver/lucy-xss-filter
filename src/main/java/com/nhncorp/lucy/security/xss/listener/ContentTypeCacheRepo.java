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

import java.lang.ref.WeakReference;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Naver Labs
 *
 */
public class ContentTypeCacheRepo {
	private static final int HARD_CACHE_CAPACITY = 1000;

	// Hard cache, with a fixed maximum capacity and a life duration
	@SuppressWarnings("serial")
	private final HashMap<String, ContentType> sHardBitmapCache = new LinkedHashMap<String, ContentType>(HARD_CACHE_CAPACITY * 4 / 3 + 1, 0.75f, true) {
		@Override
		protected boolean removeEldestEntry(final Map.Entry<String, ContentType> eldest) {
			if (size() > HARD_CACHE_CAPACITY) {

				// Entries push-out of hard reference cache are transferred to soft reference cache
				//System.out.println("sHardBitmapCache size() : " + size());
				sSoftBitmapCache.put(eldest.getKey(), new WeakReference<ContentType>(eldest.getValue()));

			/*	int cnt = 0;
				for (WeakReference<ContentType> contentTypeCacheReference : sSoftBitmapCache.values()) {
					if (contentTypeCacheReference!=null) {
						ContentType contentType = contentTypeCacheReference.get();
						if (contentType !=null) {
							 cnt++;
						}
					}
				}
				System.out.println("sSoftBitmapCache size() : " + cnt);*/
				return true;
			} else {
				return false;
			}
		}
	};

	// Soft cache for ContentTypeCache kicked out of hard cache
	private final static ConcurrentHashMap<String, WeakReference<ContentType>> sSoftBitmapCache = new ConcurrentHashMap<String, WeakReference<ContentType>>(HARD_CACHE_CAPACITY / 2);

	private ContentType getContentTypeCacheFromCache(String url) {
		// First try the hard reference cache
		synchronized (sHardBitmapCache) {
			final ContentType contentTypeCache = sHardBitmapCache.get(url);
			if (contentTypeCache != null) {
				return contentTypeCache;
			}
		}

		// Then try the soft reference cache
		WeakReference<ContentType> contentTypeCacheReference = sSoftBitmapCache.get(url);
		if (contentTypeCacheReference != null) {
			final ContentType contentTypeCache = contentTypeCacheReference.get();
			if (contentTypeCache != null) {
				// contentTypeCache found in soft cache
				return contentTypeCache;
			} else {
				// Soft reference has been Garbage Collected
				sSoftBitmapCache.remove(url);
			}
		}

		return null;
	}

	public String getContentTypeFromCache(String url) {
		ContentType contentTypeCache = getContentTypeCacheFromCache(url);
		if (contentTypeCache == null) {
			return "";
		}

		Date regdate = contentTypeCache.getRegdate();
		Date today = new Date();
		String contentType = "";

		if ((today.getTime() - regdate.getTime()) < 1000 * 3600 * 24) { // cache time out 24시간 설정
			contentType = contentTypeCache.getContentType();
		} else {
			synchronized (sHardBitmapCache) {
				sHardBitmapCache.remove(url); // 하드캐시 제거 try
			}
		}
		return contentType;
	}

	public void addContentTypeToCache(String url, ContentType contentTypeCache) {
		if (contentTypeCache != null) {
			synchronized (sHardBitmapCache) {
				sHardBitmapCache.put(url, contentTypeCache);
			}
		}
	}

	public void clearCache() {
		sHardBitmapCache.clear();
		sSoftBitmapCache.clear();
	}
}
