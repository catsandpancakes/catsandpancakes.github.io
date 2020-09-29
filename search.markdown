---
layout: page
title: Search
permalink: /search/
---
<!-- Adapted from https://blog.webjeda.com/instant-jekyll-search/#how-to-implement-jekyll-instant-search -->

<!-- Search box -->
<input type="text" maxlength="50" id="search-input" placeholder="Type here to search...">

<!-- Search params -->
<div class="search-link" id="search-container">
    <div id="results-container"></div>
</div>

<!-- Script pointing to search-script.js -->
<script src="/search/search.js" type="text/javascript"></script>
<noscript>Please enable JavaScript for search to work.</noscript>

<!-- Configuration -->
<script>
SimpleJekyllSearch({
    searchInput: document.getElementById('search-input'),
    resultsContainer: document.getElementById('results-container'),
    json: '/search/search.json'
})
</script>