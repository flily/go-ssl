package encoding

type Container struct {
	Fields []*Field
}

func NewEmptyContainer() *Container {
	c := &Container{
		Fields: make([]*Field, 0),
	}

	return c
}

func (c *Container) AddField(f *Field) int {
	c.Fields = append(c.Fields, f)
	return len(c.Fields)
}

func (c *Container) FindField(fieldID uint64) *Field {
	for _, f := range c.Fields {
		if f.FieldID() == fieldID {
			return f
		}
	}

	return nil
}

func (c *Container) FindFields(fieldID uint64) []*Field {
	fields := make([]*Field, 0)
	for _, f := range c.Fields {
		if f.FieldID() == fieldID {
			fields = append(fields, f)
		}
	}

	return fields
}
