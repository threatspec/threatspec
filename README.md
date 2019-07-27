# threatspec - continuous threat modeling, through code

[![Build Status](https://travis-ci.org/threatspec/threatspec.svg?branch=master)](https://travis-ci.org/threatspec/threatspec)
[![PyPI version fury.io](https://badge.fury.io/py/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)
[![PyPI license](https://img.shields.io/pypi/l/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)


Threatspec is an open source project that aims to close the gap between development and security by bringing the threat modelling process further into the development process. This is achieved by having developers and security engineers write threat modeling annotations as comments inside source code, then dynamically generating reports and data-flow diagrams from the code. This allows engineers to capture the security context of the code they write, as they write it. In a world of everything-as-code, this can include infrastructure-as-code, CI/CD pipelines, and serverless etc. in addition to traditional application code.

## Getting started

### Step 1 - Install threatspec

```
$ pip install threatspec
```

You'll also need to install [Graphviz](https://www.graphviz.org/) for the report generation.

### Step 2 - Initialise threatspec in your code repository

```
$ threatspec init
Initialising threatspec...

Threatspec has been initialised. You can now configure the project in this
repository by editing the following file:

    threatspec.yaml
      
```

You can configure threatspec by editing the `threatspec.yaml` configuration file which looks something like this:

```
# This file contains default configuration for a threatspec-enabled repository
# Warning: If you delete this file, threatspec will treat this directory as a normal source path if referenced by other threatspec.yaml files.

project:
  name: "threatspec project"           # Name of your project. This might be you application name or a friendly name for the code repository.
  description: "A threatspec project." # A description of the project. This will be used in the markdown report as well as the name.
imports:                               # Import other threatspec projects into this one.
  - './'                               # Current directory isn't strictly necessary as this is processed anyway. Just here as an example.
paths:                                 # Source code paths to process
  - './'                               # Parse source files in the current directory by default.
# - 'path/to/repo1'                    # You can refer to other repositories or directories as needed
# - 'path/to/repo2'                    # ... and you can do this as much as you like
# - 'path/to/source/file.go'           # You can directly reference source code files and directories
# - path: 'path/to/node_source         # You can also provide ignore paths for a path by providing a dictionary
#   ignore:                            # Any sub-paths defined in this array are ignored as source files within the path are recursively parsed
#     - 'node_modules'
# - path: 'path/to/config.py'
#   mime: 'text/x-python'              # You can explicitly set the mime type for files if needed

```

### Step 3 - Annotate your source code with security concerns, concepts or actions

```
// @accepts arbitrary file writes to WebApp:FileSystem with filename restrictions
// @mitigates WebApp:FileSystem against unauthorised access with strict file permissions
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}
```

### Step 4 - Run threatspec against your source code

```
$ threatspec run
Running threatspec...

Threatspec has been run against the source files. The following threat mode file
has been created and contains the mitigations, acceptances, connections etc. for
the project:

    threatmodel/threatmodel.json

The following library files have also been created:

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json

```

### Step 5 - Generate the threat model report

```
$ threatspec report
Generating report...
The following threat model visualisation image has been created: ThreatModel.md.png
The following threat model markdown report has been created: ThreatModel.md
```

## Example report

<img src="https://github.com/threatspec/threatspec/raw/master/doc/report.png" width="300">

See https://github.com/threatspec/threatspec_example_report.

## Getting help

For more information, use the command line help flag.

```
$ threatspec --help
Usage: threatspec [OPTIONS] COMMAND [ARGS]...

  threatspec - continuous threat modeling, through code

  threatspec is an open source project that aims to close the gap between
  development and security by bringing the threat modelling process further
  into the development process. This is achieved by having developers and
  ...
```

## Annotating your code

### Supported file types

At the heart of threatspec there is a parser that reads source code files and processes any annotations found in those files. It uses a Python library called `comment_parser` to extract those comments. The `comment_parser` library determines the file's MIME type in order to know which type of comments need to be parsed. The supported file MIME types are:

| Language    | Mime String              |
|------------ |------------------------- |
| C           | text/x-c                 |
| C++/C#      | text/x-c++               |
| Go          | text/x-go                |
| HTML        | text/html                |
| Java        | text/x-java-source       |
| Javascript  | application/javascript   |
| Shell       | text/x-shellscript       |
| XML         | text/xml                 |

An unknown MIME type will result in a warning and the file will be skipped.

See https://github.com/jeanralphaviles/comment_parser for details.

In addition to these, threatspec will also soon parse the following files natively:

- YAML
- JSON
- Plain text

If the MIME type for a file can't be determined, or if it is incorrect, you can override the MIME type for a path in the `threatspec.yaml` configuration file.

### Comment types

There are four main comment types supported by threatspec.

#### Single-line

A single-line comments are the most common use-case for threatspec as they allow you to capture the necessary information as close as possible to the code. An example would be

```
// @mitigates WebApp:FileSystem against unauthorised access with strict file permissions
func (p *Page) save() error {
```

#### Multi-line

If you want to capture multiple annotations in the same place, you could use multiple single-line comments. But you can also use multi-line comments instead:

```
/*
@accepts arbitrary file writes to WebApp:FileSystem with filename restrictions
@mitigates WebApp:FileSystem against unauthorised access with strict file permissions
*/
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}
```

More importantly, if you want to use the extended YAML syntax (see below), you'll need to use multi-line comments:

```
/*
@mitigates WebApp:FileSystem against unauthorised access with strict file permissions:
  description: |
    The file permissions 0600 is used to limit the reading and writing of the file to the user and root.
    This prevents accidental exposure of the file content to other system users, and also protects against
    malicious tampering of data in those files. An attacker would have to compromise the server's user
    in order to modify the files.
*/
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}
```

#### Inline

You can add comments to the end of lines that also contain code. This can be useful, but might result in rather long lines. Probably best to use these for @review annotations.

```
        err = ioutil.WriteFile("final-port.txt", []byte(l.Addr().String()), 0644) // @review WebApp:Web Is this a security feature?
```

#### YAML and JSON

Finally, the last comment type isn't really a comment at all. Rather, it's addtional keys in JSON or YAML data files using the `x-threatspec` extension key. This was primarily chosen to be compatible with OpenAPI/Swagger files but might work in other circumstances. The rest of the threatspec annotation is essentially the same. So a very simple example would be something like:

```
servers:
  - url: http://petstore.swagger.io/v1
    x-threatspec: "@exposes Petstore:Web to Man in the Middle (#mitm) with lack of TLS"
```

A more complete example using the extended syntax just uses the threatspec annotation as a key:

```
    post:
      summary: Create a pet
      operationId: createPets
      tags:
        - pets
      x-threatspec:
        "@exposes Petstore:Pet:Create to Creation of fake pets with lack of authentication":
          description: "Any anonymous user can create a pet because there is no authentication and authorization"
```

### Summary of annotations

Here is a quick summary of each supported annotation type. For a full description, see the Annotations section below.

| Annotation | Example |
| ---------- | ------- |
| @component - a hierarchy of components within the application or service. | `@component MyApp:Web:Login` |
| @threat - a threat | `@threat SQL Injection (#sqli)` |
| @control - a mitigating control | `@control Web Application Firewall (#waf)` |
| @mitigates - a mitigation against a particular threat for a component, using a control | `@mitigates MyApp:Web:Login against Cross-site Request Forgery with CSRF token generated provided by framework` |
| @exposes - a component is exposed to a particular threat | `@exposes MyApp:CICD:Deployment to rogue code changes with lack of separation of duty` |
| @accepts - the acceptance of a threat against a component as unmitigated | `@accepts #api_info_diclosure to MyService:/api with version information isn't sensitive` |
| @transfers - a threat is transferred from one component to another | `@transfers auth token exposed from MyService:Auth:#server to MyService:Auth:#client with user must protect the auth token` |
| @connects - a logical, data or even physical connection from one component to another | `@connects MyService:Product:Search to MyService:Product:Basket with Add selected product to basket` |
| @tests - the test of a control for a component | `@tests CSRF Token for MyService:Web:Form` |
| @review - a note for a component to be reviewed later | `@review Web:Form Shouldn't this mask passwords?` |

### Custom data using YAML

Threatspec now supports an extended syntax which uses YAML. This allows you to provide additional data that can then be used in reports, or any other processing of the JSON files. There is one special `description` field that is supported by default and is used by the default reporting if provided. As in the above example, you can use `description` to provide any additional context using a multi-line comment:

```
/*
@mitigates WebApp:FileSystem against unauthorised access with strict file permissions:
  description: |
    The file permissions 0600 is used to limit the reading and writing of the file to the user and root.
    This prevents accidental exposure of the file content to other system users, and also protects against
    malicious tampering of data in those files. An attacker would have to compromise the server's user
    in order to modify the files.
*/
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}
```

You can also add any other data fields you like, which can then be used in custom reports. For example:

```
/*
@exposes WebApp:App to XSS injection with insufficient input validation:
  description: An attacker can inject malicious javascript into the web form
  impact: high
  owner: Engineering
  ref: #TRACKER-123
  
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	renderTemplate(w, "edit", p)
}
```

### Ways of capturing information

There are two main use-cases for using threatspec, and so threatspec can be used in a couple of different ways.

#### Capturing key information in the moment while writing code

The first use-case is as a developer (or other engineer) writing code, and wanting to capture security context such as possible threats, decisions, questions, assumptions etc. As you're in the middle of writing code, you might not have the full big-picture context immediately available, but you want to quickly capture important information there and then, with minimal effort. Threatspec does this by keeping you in the IDE, thereby minimising context switching and delays.

The free-text style of threatspec annotations are ideally suited for this case. Let's say you are writing a database query and are using parameterised queries. It's possible that you're doing this simply because you've been told its best practice. But you're clever and you know its best practice because it helps to mitigate against threats like SQL injection. Without having the full context in your head, you quickly write the comment:

```
// @mitigates MyApp:Web:Backend against SQL Injection with use of parameterised queries
```

You've now captured a very important security decision, with minimal effort. This can now be displayed in the much wider context by generating a report. What threatspec does when it parses your comment is turn each of the elements into identifiers. You don't have to know about these identifiers right now, as you're just capturing key information.

For example, the `SQL Injection` threat above would have the identifier `#sql_injection`. Now, if somewhere else in your project somebody has already created a SQL injection threat, but they used the identifier `#sqli` then that's fine. There will be some duplication, but you can quickly spot that in the report and iterate to reduce the duplications. But most importantly, you capture the necessary information in a meaningful and efficient way. The big-picture view will naturally emerge and evolve over time with the code base.


#### Capturing data in structured threat modeling sessions

The other use case for threatspec is as a way to capture information in threat modeling sessions. Let's say you to get together as a team before starting work on a new feature. This threat modeling session will serve as a design and architecture session as well as for thinking about threats. You'll probably start off sketching designs and architectures on a whiteboard, and so you'll want to start capturing key components as they're discussed. Threatspec lets you do this in any IDE, just by using a plaintext file:

```
@component External:User (#user)
@component MyApp:Web:LoadBalancer (#lb)
@component MyApp:Web:WebServer (#web)
@component MyApp:API:Product (#product_api)
@component MyApp:API:Users (#users_api)
```

Running `threatspec report` at this stage will already generate a visual hierarchy of the components. You'll probably want to make logical, data flow or other connections between the components as well. So you might capture something like:

```
@connects #user to #lb with HTTPS
@connects #lb to #web with HTTPS
@connects #user to #product_api with Product Search
@connects #user to #users_api with User Management
```

Now that a bit of an architecture or data flow is starting to emerge, it's probably a good time to start thinking about potential threats. As this is a structured session, it's a great opportunity to write the threats in a more structured way that can evolve into a library of threats. Capturing the threats in the same file might look something like this:

```
# Threats

@threat Authentication Info Disclosure (#auth_info_disclosure):
  description: An attacker can obtain information about existing users to the system
  
@threat Expensive Query Denial of Service (#query_dos):
  description: An attacker can submit many queries that are expensive for the backend service to run
    resulting in a denial of service for that service.

# Exposures

@exposes #users_api to #auth_info_disclosure with broken role based access control
  description: |
    If an authentication and authorization model is broken, and attacker might be able to
    retrieve information about other users from the Users API.
    
@exposes #product_api to #query_dos with suboptimal product search query:
  description: The way product queries is done is inefficient and a large number could easily take down the service.
```

Running `threatspec report` now will start to look like a traditional threat model document. The difference is that as you start adding to your code base, you can start moving the annotations to the relevant code classes and functions so that the threat model continues to stay in sync. And if the architecture changes, that's no problem either. The generated report will always reflect what has been documented in the code.

### Skipping annotations

To stop an annotation from being parsed and reported on, you can put a string in front of the @action tag. Any string will do, but we suggest you use the word `@skip` so it's easy to search for.

```
// @skip @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information
func main() {
```

## Running threatspec

So far we've looked at how threatspec can be embedded within source files. This section looks at how threatspec can be used within code repositories and even across repositories.

### In a single repository

When you first use threatspec, you'll likely initialise it in a code repository that you're just starting or have already been working on, rather than creating a new repository specifically for threatspec. This allows you to quickly get started with using threatspec in an evolving code base. Using the `threatspec.yaml` configuration file you can tweak how the various paths within the repository are processed.

### Across multiple repositories

As your code base or use of threatspec grows, you may need to generate the bigger threat modeling picture from multiple repositories. These could be different repositories for the same application, but could also be entirely different applications. Or, a mixture of application and infrastructure deployment repositories. At this stage you may want to create a new repository specifically for threatspec that has a configuration file that points to various other repositories. When threatspec processes the `imports` section of the configuration file, it loads the threat model and library files from each import path. This allows you to "glue" multiple repositories together into a single view.

Let's say you had the following repositories, each containing a `threatspec.yaml` file and annotations within their source files:

- src/myapp-api
- src/myapp-web
- src/myapp-deployment
- src/auth-service

In this example, auth-service would be a service shared across the organisation. You could create a new repository called `src/myapp-threatmodel` containing the following `threatspec.yaml` file:

```
project:
  name: MyApp
  description: My Application Service
imports:
  - ../myapp-api
  - ../myapp-web
  - ../myapp-deployment
  - ../auth-service
paths:
  - ./
```

Running threatspec in the myapp-threatmodel repo would generate a threat model report across the entire MyApp code base, but also including the auth service.

## Generating reports

Report generation in threatspec is there to allow you to take a step back and look at the wider context. This allows the bigger picture to naturally and organically emerge from the more day-to-day tactical decisions and assumptions. There's no fixed point at which you have to generate the report, but some suggestions are:

- Generating it locally on your development machine as a sense-check after adding in new annotations
- Automatically generating documentation and therefore the threat model report as part of a CI/CD pipeline
- Prior to a team or multi-team threat modeling session
- As part of an architecture review process
- As input into an AppSec process such as internal pentesting or code review

### The default report

The default report aims to provide a visual context as well as the details. It does this by generating a visualisation of the components, threats and controls in the form of a graph. It also provides tables of the threats, connections and reviews. This is all packaged up as a Markdown document. If you'd like to generate a PDF of the report, we suggest you use your browser's Print to PDF feature.

### Other reports

There are a couple of other basic report formats supported by threatspec.

#### Text report

There is a basic `text` report which provides a summary as a basic ASCII text file.

#### JSON report

There is also a `json` report that will generate a single JSON file for all of the mitigations, exposures etc. and all of the threats, controls and components that are in scope. The source data files are merged together for simpler processing. For example, where an object originally referenced a control by its identifier, that key now points to a copy of the whole control object. This saves having to cross reference data.

You can use the JSON report file to create whatever custom visualisation or report as you see fit. Examples include:

- Writing a script to parse the JSON file and insert the data into another data store (e.g. a database or JIRA)
- Writing a simple CI/CD gate script that breaks the build under certain conditions like too many exposures
- Building your own custom visualisation or reporting tool

### Custom reports

The reporting system in threatspec uses the Python Jinja2 templating library. It also allows you to specify your own template file directly from the command line using the `template`  output option. This allows you to easily create custom reports in whatever text format you need, without having to code something from scratch. The data that is made available to the template is the same as you get by running the `json` report, and it is passed in using the `report` variable. A very simple custom report might look like:

```
*******************************************************************************
{{ report.project.name }} Threat Model
*******************************************************************************

{{ report.project.description }}
```

See http://jinja.pocoo.org/ for more information on the Jinja2 templating library.

## Annotations

Threatspec is based around annotating code with security related concepts. The code could be traditional application source code, but also Infrastructure-as-code. Comments are used at the point where the threat is most relevant, and by annotating the code you keep the threat model closest to the source - especially in a world of everything-as-code. This results in a living, evolving threat model document that plays well with existing software engineering practices such as Agile, Lean, code peer review, continuous testing and continuous deployment.

### Threats

As you can imagine, a lot of threat modeling involves talking about threats. In the context of threat modeling, a threat is simply something that could go wrong. We typically focus on cyber security threats to technical systems, but not necessarily. In threatspec, a threat is basically just a string or an identifier to a string (see the Identifiers section below). Documented threats are stored in threat library JSON files and can be used across the code. In fact, it's sensible to build libraries of threats that can be shared across projects within your organisation, or even released as open source for others to use.

A threat in threat modeling isn't the same thing as a vulnerability. You cannot have a vulnerability in an application that only exists as a whiteboard drawing, but you can sensibly talk about possible threats to that application. Essentially, a vulnerability is a materialised threat. Threat modeling, and threatspec in particular, can help add context to other Application Security (AppSec) processes.

### Controls

Threats are preferably mitigated in some way, and this typically involves implementing a technical control. Of course, in a threat modeling session, you'll probably be talking about which potential controls can be used to mitigate against different threats. As part of the general brainstorming process, you might want to capture a range of different possible controls of varying complexity and effectiveness. In threatspec, you might well be implementing a control in the code that you're writing, simply by following secure coding best practices. As for threats, controls are just strings to identifiers.

### Components

Components are the basic building blocks of your application or service. Whether you're looking at things from an architecture perspective, or as a data flow, components are the different bits that are somehow related and connected. Threatspec doesn't require you to interpret components in any particular way, so a single threat model can combine a mixed of architectural components, data flow processes, even elements of a user interface.

Hierarchy is achieved by separating related components using the colon character (":"). You can nest however deeply you need, and components can appear at any point in any part of other hierarchy. It only really has to make sense in the context of your application or service, and organisation.

Here's what a typical web user interface component might look like: `MyApp:Web:LoginForm`. Within the MyApp application, we have a Web component that contains a LoginForm. See the examples below for many more examples.

There are two special components which are particularly useful for threat modeling APIs. One of the challenges of APIs and microservices is that you don't always know the full architecture in advance. The `#server` and `#client` special components let you refer to any current or future client of a server, without committing to the client being in any particular part of the architecture. For an example, see the "Transfers" section below.

Finally, components bring with them a challenge of identity. How do we know that the database component in `MyApp:Product:Database` is the same thing as the database component in `MyApp:Users:Database`? Threatspec assumes that they're different by default, because it generates a component ID using the full path. If they are in fact actually the same thing, you can state that by putting the primary component (the preferred way of referring to it) in parentheses after the alternative path. For example, `MyApp:Product:Database` and `MyApp:Users:Database (MyApp:Product:Database)` both refer to the same Database component.

### Identifiers

Identifies are short-hand ways of referring to unique threats, components or controls (which we'll refer to as library objects). When parsing annotations, threatspec generates an ID for each new library object, and if the ID isn't known, it adds the new object to the respective library. You can also refer directly to the library object using the ID. To do this, you can specify an explicit ID by putting it in parentheses. For example, you can reference the threat `SQL Injection (#sqli)` simply as `#sqli` instead of `SQL Injection`.

### Mitigates

A mitigation reduces the potential impact or likelihood of a threat to a component. This is generally implemented as a technical control. In threat modeling we can talk about potential mitigations against hypothetical threats, and in threat-modeling-as-code we can document specific coding practices, libraries or architecture decisions as mitigations against a particular threat. For example, you might mitigates against a SQL injection threat by using parameterised queries.

Pattern: `@mitigates (?P<component>.*?) against (?P<threat>.*?) with (?P<control>.*)`

Examples:

* `@mitigates MyApp:Web:Login against Cross-site Request Forgery with CSRF token generated provided by framework`
* `@mitigates MyAPI:/ against DoS through excessive requests with use of a load balancer`
* `@mitigates MyService:Crypto:Keys against weak key material with use of a secure random number generator (#PRNG)`

```
// @mitigates WebApp:FileSystem against unauthorised access with strict file permissions
func (p *Page) save() error {
	filename := p.Title + ".txt"
	return ioutil.WriteFile(filename, p.Body, 0600)
}
```

### Accepts

Some threats are perceived to be relatively insignificant and therefore don't really need to be mitigated. In this case you can accept the threat. You might choose to simply ignore the threat and not even document it, but it's still worth keeping a level of visibility for accepted threats. This is because a number of smaller seemingly insignificant threats can actually pose a significant compound threat, so making these visible in threat modeling sessions is always worth it. You can of course always accept even a significant threat, possibly due to feature delivery pressures, and keeping these visible helps to highlight the growing cyber security debt your application or service is carrying.

Pattern: `@accepts (?P<threat>.*?) to (?P<component>.*?) with (?P<details>.*)`

Examples:

* `@accepts file is read by system users to MyApp:Configuration with only admin users have system access`
* `@accepts data breach of publicly available information to MyApp:AWS:S3:CustomerData with low chance of bucket is discovered by attacker`
* `@accepts #api_info_diclosure to MyService:/api with version information isn't sensitive`

```
// @accepts arbitrary file reads to WebApp:FileSystem with filename restrictions
func loadPage(title string) (*Page, error) {
	filename := title + ".txt"
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &Page{Title: title, Body: body}, nil
}
```

### Transfers

Threats can be transferred from one component to another, typically because the new component mitigates the threat in some way. A classic example of this would be transferring the threat of SQL injection from the web application to a Web Application Firewall (WAF). Technically the threat hasn't gone away, but the WAF is now responsible for mitigating it, and probably (hopefully?) does so using clever technology.

Another interesting use case for transfers is where a particular service component will do its job mitigating against certain threats, but isn't in a position to mitigate all threats. Some threats must be mitigated by users of the service. For example, a web service might securely store user credentials in the backend, but the user is also responsible for not disclosing their credentials. The threat of accidental exposure of credentials is mitigated by the service, but also transfer to the client.

Pattern: `@transfers (?P<threat>.*?) from (?P<source_component>.*?) to (?P<destination_component>.*?) with (?P<details>.*)`

Examples:

* `@transfers #sqli from MyApp:Web to #WAF with use of WAF data validation`
* `@transfers auth token exposed from MyService:Auth:#server to MyService:Auth:#client with user must protect the auth token`
* `@transfers sensitive data disclosure from MyApp:AWS:S3:Bucket to MyApp:AWS:BucketPolicy with use of bucket policy to restrict access`

```
// @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information
func main() {
	flag.Parse()
	http.HandleFunc("/view/", makeHandler(viewHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveHandler))

	if *addr {
		l, err := net.Listen("tcp", "127.0.0.1:0")
```

### Exposes

If a threat isn't mitigated, transferred or accepted, it's basically left exposed. This should be the default state for new threats, until a decision has been made on what to do with them. Note that an exposed threat modeling threat doesn't necessarily equate to a vulnerability, but it highlights where you might expect to find them.

Pattern: `@exposes (?P<component>.*?) to (?P<threat>.*?) with (?P<details>.*)`

Examples:

* `@exposes Web:Form to #XSS with lack of input validation`
* `@exposes MyService:Basket to price tampering with lack of backend validation`
* `@exposes MyApp:CICD:Deployment to rogue code changes with lack of separation of duty`

```
// @exposes WebApp:App to XSS injection with insufficient input validation
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	renderTemplate(w, "edit", p)
}
```

### Connects

The relationship between components in a hierarchy are inferred from the component naming convention (see Components below). If you want to explicitly document connectivity between components, you can do this with the @connects tag. This allows you to draw architecture diagrams or data-flow diagrams, even before a single line of actual code has been written.

Pattern: `@connects (?P<source_component>.*?) (?P<direction>with|to) (?P<destination_component>.*?) with (?P<details>.*)`

Examples:

* `@connects User:Browser to MyApp:Web:Nginx with HTTPS/TCP/443`
* `@connects MyService:Product:Search to MyService:Product:Basket with Add selected product to basket`
* `@connects MyService:AWS:S3 with MyService:AWS:S3BucketPolicy with policy enforcement`

```
// @connects User:Browser to MyService:Product:View with category
// @connects MyService:Product:View to MyService:Product:Search with search by category
// @connects MyService:Product:Search to MyService:Product:View list of products
// @connects MyService:Product:View to User:Browser with table of products by category
```

### Tests

Identifying threats is great. Identifying mitigations against those threats is better. Implementing those mitigations is even better. Testing that those mitigations work, well that's just amazing. This action allows you to comment which unit or integration code is testing a particular control. This helps you to ensure the mitigations are working as expected and makes that visible in the threat model. These can also act as security regression tests, to prevent previously fixed threats returning. It's worth noting that writing tests which validate the control behaviour directly is great, but you might also want to consider how you could write offensive tests that fail as a result of the control. This can help bridge the gap where the control is working as expected, but where another factor has resurfaced the threat.

Pattern: `@tests (?P<control>.*?) for (?P<component>.*)`

Examples:

* `@tests CSRF Token for MyService:Web:Form`
* `@tests Strict File Permissions for MyApp:Config`
* `@tests #PRNG for Web:Auth`

```
// @tests SecureRandom for App:Crypto:Certificates
def test_prng_entropy():
  prng = crypto.SecureRandom()
```

### Review

Threat modeling in code, especially unfamiliar code, can at times look a bit like a code review. If you're not the one who is writing or has written the code, questions may crop up that are worth flagging in a threat modeling session. You can use the @review tag to simply highlight a question or possible concern to be reviewed or discussed later.

Pattern: `@review (?P<component>.*?) (?P<details>.*)`

Examples:

* `@review Web:Form Shouldn't this mask passwords?`
* `@review MyService:Auth this might not be a secure crypto algorithm in this situation`
* `@review MyApp:Database Where do these credentials come from?`

```
  // @review MyService:Web Shouldn't this be using TLS?
	http.ListenAndServe(":8080", nil)
```
