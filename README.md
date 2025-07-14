# What is it?

BurpSidian is a BurpSuite extension that automatically creates markdown files for visited pages. The extension is continuously watching SiteMap for InScope URL's and creates the markdown for you. The extension does not create markdown for resource files (line 128) and instead creates a seperate "Static Inclusions.md" with a list of the found inclusions.

### Key Features:
- Creates md with the method in the file name.
- Includes a link.
- Lists all inputs found and their location.
- Includes a sample request and response.
- Shows comments, inline scripts, and forms found in the body.

### Page template:

Filename: directory?urlParams(if any).md
#### Link: link
---
#### Description:
Needs to be manually updated

---
#### Inputs:
- list 
- of 
- params
---
#### Sample Request:
```HTTP
request
```

---
#### Sample Response:
```HTTP
response up to </head>
```

---
#### Found Hidden Elements:
```HTML
<input type="hidden" name="password" value="password"/>
```
#### Found comments:
```HTML
<!-- This section will only display if comment(s) are found -->
```
---
#### Found Script Tags:
```HTML
<script>
	//this section will only display if inline script(s) are found
</script>
```
---
#### Found HTML Forms:
```HTML
<form action="post"...>
	<!-- This section will only display if form element(s) are found --->
</form>
```

The above template can be pretty long as its not really filtering on "interesting" elements/scripts/comments. Its just reading it for you and documenting it.

# How to use

Once imported into burp and loaded, you must first set your scope.
##### IF SCOPE IS NOT SET, THE EXTENSION WILL NOT CREATE ANY MARKDOWN.
Once the scope has been set, you may have noticed a new "BurpSidian" tab. This is a pretty bare bones tab (because I couldn't figure out how to put settings into BurpSettings) with two settings. An "Obsidian Vault" file browse button, and a "Start Monitoring" button.

The file browser allows you to choose the directory where you want the map pages to be created. It defaults to ``os.path.expanduser('~')``

Once you have selected the path you want, and your scope has been set, click the "Start Monitoring" button.

This enables the functionality of creating markdown.

When a new page is browsed to, the extension will automatically create the map page for you.


# Current Issues
This extension was created over two days using jython. There are bound to be bugs and issues. Please post in the issues as I would like to update and maintain this repo, I find the extension very helpful. 

One bug that may still be ongoing is that if a page that has already been visited is visited again, but with a new input parameter somewhere in the request, it won't update the md. This may require a refactor.

Secondly, if the burp state gets too large, the extension will use a lot of resources (if running in a vm with 4 cores and limited ram). It is recommended that you map first before proxying heavy scan traffic through burp (i.e. using sqlmap --proxy and the like). I noticed this start to become a problem once the burp http history hit about 12k requests. It was fine up to about 25k requests, and got worse from there. 

# Future Update Plans

- More settings including:
	- enable/disable comments, forms, inline js
	- enable/disable skip over resource files
	- enable/disable include sample request
	- enable/disable include sample response
	- create "Finding" pages based off issues found in burps passive audit
	- checklist items for common vulnerability tests (as a reminder of where you left off testing the page)
		- additionally, a finding button that allows you to create a finding page from the checklist item.

