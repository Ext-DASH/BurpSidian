package burp.extension.models;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.MimeType;

//processed request/response
public class PlainTextRequestResponse {
    private HttpRequest request;
    private HttpResponse response;

    private String fileName;
    private String urlPath; //done
    private String url; //done
    private List<HttpHeader> requestHeaders; //done
    private List<ParsedHttpParameter> requestParameters; //done
    private String requestBody; //done
    private String responseHeaders; //done
    private String responseBody; //done
    private MimeType contentType; //done
    private String reqMethod; //done
    private List<String> comments;
    private List<String> forms;
    private List<String> inlineJS;
    private List<String> hiddenElements;
    public String getResponseHeaders;

    private String method;

    //Constructor
    public PlainTextRequestResponse(HttpRequest request, HttpResponse response) {
        this.request = request;
        this.response = response;
    }

    //factory
    public static PlainTextRequestResponse from(HttpRequest request, HttpResponse response) {
        PlainTextRequestResponse obj = new PlainTextRequestResponse(request, response);
        obj.processRequest();
        obj.processResponse();
        return obj;
    }
    //getters
    public String getFileName() { return this.fileName; }


    //methods
    private void processRequest() {
        this.url = request.url();
        this.urlPath = request.path();
        if ("/".equals(this.urlPath)) {
            this.fileName = "Home Page";
        } else {
            int i = this.urlPath.indexOf('?');
            String noQuery = (i >= 0) ? this.urlPath.substring(0, i) : this.urlPath;
            this.fileName = noQuery.replace('/', ' ');
        }
        this.requestHeaders = request.headers();
        this.requestBody = request.bodyToString();
        this.reqMethod = request.method();
        this.requestParameters = request.parameters();
        this.method = request.method();
        

    }

    private void processResponse () {
        this.contentType = response.statedMimeType();
        this.responseBody = response.bodyToString();
        //if its content type is text/html
        if (this.contentType.equals(MimeType.valueOf("HTML"))) {
           this.comments = CommentExtractor.extractHtmlComments(responseBody);
           this.forms = FormExtractor.extractForms(responseBody);
           this.hiddenElements = HiddenElementsExtractor.extractHiddenElements(responseBody);
           this.inlineJS = InlineJSExtractor.extractInlineJS(responseBody);
        }
    }

    // getters
    public String getResponseHeaders() {
        return this.responseHeaders;
    }
    public String getRequestBody() {
        return this.requestBody;
    }
    
    public String getResponseToHead() {
        Pattern pattern = Pattern.compile("(?is)(.*?)</head>");
        Matcher matcher = pattern.matcher(this.response.toString());
        if (matcher.find()) {
            return matcher.group(0);
        }

        return "";
    }

    public String getUrl() {
        return this.url;
    }

    public String getMethod() {
        return this.method;
    }

    public List<ParsedHttpParameter> getParameters() {
        return this.requestParameters;
    }


    public List<String> getComments() {
        return this.comments;
    }

    public List<String> getInlineJS() {
        return this.inlineJS;
    }

    public List<String> getForms() {
        return this.forms;
    }

    public List<String> getHiddenElements() {
        return this.hiddenElements;
    }

    public String getPath() {
        return this.urlPath;
    }

    public String getFullRequest() {
        return this.request.toString();
    }
    
}

