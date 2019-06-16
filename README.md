# threatspec

## Getting started

### Step 1 - Install threatspec

```
$ pip install threatspec
```

You'll also need to install [Graphviz](https://www.graphviz.org/) for the report generation. 

### Step 2 - Initialise threatspec in your code repository

```
$ threatspec init
```

You can edit the `threatspec.yaml` configuration file.

### Step 4 - Annotate your source code with security concerns, concepts or actions

```
// @accepts arbitrary file writes to WebApp:FileSystem with filename restrictions
// @mitigates WebApp:FileSystem against unauthorised access with strict file permissions
// func (p *Page) save() error {
//     filename := p.Title + ".txt"
//     return ioutil.WriteFile(filename, p.Body, 0600)
// }
```

### Step 3 - Run threatspec against your source code

```
$ threatspec run
```

### Step 4 - Generate the threat model report

```
$ threatspec report
```

Threatspec will create a number of files:

  * ThreatModel.md
  * threatmodel/threatmodel.json
  * threatmodel/threats.json
  * threatmodel/controls.json
  * threatmodel/components.json
