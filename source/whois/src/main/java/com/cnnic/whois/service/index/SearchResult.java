package com.cnnic.whois.service.index;

import java.util.LinkedList;
import java.util.List;
/**
 * search result bean,for search query
 * @author nic
 *
 * @param <T>
 */
public class SearchResult<T> {

	private double searchTime;

	private long totalResults;

	private List<T> resultList = new LinkedList<T>();
	/**
	 * get search time
	 * @return
	 */
	public double getSearchTime() {
		return searchTime;
	}

	public void setSearchTime(
			double searchTime) {
		this.searchTime = searchTime;
	}

	public long getTotalResults() {
		return totalResults;
	}

	public void setTotalResults(
			long totalResults) {
		this.totalResults = totalResults;
	}

	public List<T> getResultList() {
		return resultList;
	}

	public void setResultList(
			List<T> issueList) {
		this.resultList = issueList;
	}

	public void addResultItem(
			T resultItem) {
		resultList
				.add(resultItem);
	}

}
