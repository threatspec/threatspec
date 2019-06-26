# threatspec

[![Build Status](https://travis-ci.org/threatspec/threatspec.svg?branch=master)](https://travis-ci.org/threatspec/threatspec)
[![PyPI version fury.io](https://badge.fury.io/py/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)
[![PyPI license](https://img.shields.io/pypi/l/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/threatspec.svg)](https://pypi.python.org/pypi/threatspec/)

## Getting started

Threatspec is an open source project that aims to close the gap between development and security by bringing the threat modelling process further into the development process. This is achieved by having developers and security engineers write threat specifications alongside code, then dynamically generating reports and data-flow diagrams from the code. This allows engineers to capture the security context of the code they write, as they write it.

### Step 1 - Install threatspec

```
$ pip install threatspec
```

You'll also need to install [Graphviz](https://www.graphviz.org/) for the report generation.

### Step 2 - Initialise threatspec in your code repository

```
$ threatspec init
```

You can configure threatspec by editing the `threatspec.yaml` configuration file which looks something like this:

```
# This file contains default configuration for a threatspec-enabled repository
# Warning: If you delete this file, threatspec will treat this directory as a normal source path if referenced by other threatspec.yaml files.

project:
  name: "threatspec project"           # Name of your project. This might be you application name or a friendly name for the code repository.
  description: "A threatspec project." # A description of the project. This will be used in the markdown report as well as the name.
paths:                                 # Paths to process. If a threatspec.yaml file exists, library data source paths are loaded recursively.
  - './'                               # Parse source files in the current directory by default.
# - 'path/to/repo1'                    # You can refer to other threatspec repositories and respective threatspec.yaml files are loaded.
# - 'path/to/repo2'                    # ... and you can do this as much as you like
# - 'path/to/source/file.go'           # You can directly reference source code files and directories
# - path: 'path/to/node_source         # You can also provide ignore paths for a path by providing a dictionary
#   ignore:                            # Any sub-paths defined in this arrary are ignored as source files within the path are recursively parsed
#     - 'node_modules'
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
```

### Step 5 - Generate the threat model report

```
$ threatspec report
```

Threatspec will create a number of files:

  * ThreatModel.md
  * ThreatModel.gv
  * ThreatModel.gv.png
  * threatmodel/threatmodel.json
  * threatmodel/threats.json
  * threatmodel/controls.json
  * threatmodel/components.json

## Example report

<img src="https://github.com/threatspec/threatspec/raw/master/doc/report.png" width="300">

See https://github.com/threatspec/threatspec_example_report.

## Getting help

For more information, use the command line help flag.

```
$ threatspec --help
```

## Annotations

Threatspec is based around annotating code with security related concepts. The code could be traditional application source code, but also Infrastructure-as-code. Comments are used at the point where the threat is most relevant, and by annotating the code you keep the threat model closest to the source - especially in a world of everything-as-code. This results in a living, evolving threat model document that plays well with existing software engineering practices such as code reviewed, continuous testing and continuous deployment.

### Threats

As you can imagine, a lot of threat modeling involves talking about threats. In the context of threat modeling, a threat is simply something that can go wrong. We typically focus on cyber security threats to technical systems, but not necessarily. In threatspec, a threat is basically just a string or an identifier to a string (see the Identifiers section below). Documented threats are stored in threat library JSON files and can be used across the code. In fact, it's sensible to build libraries of threats that can be shared across projects within your organisation, or even released as open source for others to use.

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

Identifies are short-hand ways of referring to unique threats, components or controls (which we'll refer to as library objects). When parsing annotations, threatspec generates an ID for each new library object, and if the ID isn't known, it adds the new object to the respective library. You can also refer directly to the library object using the ID. To do this, you can specify an explicit ID by putting it in parentheses. For example, you can reference the threat `SQL Injection (#sqli)` simply as `#sqli` instead of `SQL Injection`. Anything that comes after the ID but before other parts of an annotation is treated as extra details that don't apply to the general library component.

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
* `@accepts data breach of publicly available information to MyApp:AWS:S3:CustomerData with low chance of bucket is discovered by attacker` (BAD IDEA!!)
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

### Review

Threat modeling in code, especially unfamiliar code, can at times look a bit like a code review. If you're not the one who is writing or has writsten the code, questions may crop up that are worth flagging in a threat modeling session. You can use the @review tag to simply highlight a question or possible concern to be reviewed or discussed later.

Pattern: `@review (?P<component>.*?) (?P<details>.*)`

Examples:

* `@review Web:Form Shouldn't this mask passwords?`
* `@review MyService:Auth this might not be a secure crypto algorithm in this situation`
* `@review MyApp:Database Where do these credentials come from?`

```
  // @review MyService:Web Shouldn't this be using TLS?
	http.ListenAndServe(":8080", nil)
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
